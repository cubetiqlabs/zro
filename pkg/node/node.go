package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "github.com/cubis/zro/api/proto/v1"
	"github.com/cubis/zro/pkg/config"
	controlauth "github.com/cubis/zro/pkg/control/auth"
	controlgrpc "github.com/cubis/zro/pkg/control/grpc"
	"github.com/cubis/zro/pkg/control/server"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/crypto"
	"github.com/cubis/zro/pkg/dataplane/derp"
	"github.com/cubis/zro/pkg/dataplane/netcfg"
	"github.com/cubis/zro/pkg/dataplane/router"
	"github.com/cubis/zro/pkg/dataplane/tun"
	"github.com/cubis/zro/pkg/dataplane/wireguard"
	"github.com/cubis/zro/pkg/p2p/disco"
	"github.com/cubis/zro/pkg/p2p/puncher"
	"github.com/cubis/zro/pkg/p2p/stun"
	"github.com/cubis/zro/pkg/tunnel"
	"github.com/google/uuid"
)

// Daemon represents the running zro-node client agent.
type Daemon struct {
	cfg          *config.NodeConfig
	keyPair      *crypto.KeyPair
	nodeID       uuid.UUID
	networkID    string // ZeroTier-style 16-hex network ID
	overlayIPv4  string
	overlayIPv6  string
	primaryPoP   core.EdgePoP
	secondaryPoP *core.EdgePoP
	popMu        sync.RWMutex
	peers        map[string]core.Node // pubKey -> node
	peersMu      sync.RWMutex

	tunDev       tun.Device
	wgManager    *wireguard.Manager
	routingTable *router.Table
	udpConn      *net.UDPConn
	discoEngine  *disco.Engine
	derpClient   *derp.Client
	tunnelClient *tunnel.Client
	httpClient   *http.Client
	token        controlauth.TokenHolder // bearer token issued at enrollment
	grpcClient   *controlgrpc.Client

	// Zero-Trust Inbound Firewall & Mesh Listeners
	policyMu      sync.RWMutex
	allowedPorts  []string // e.g. ["5432/tcp"]
	defaultDeny   bool     // default true for zero-trust
	allowedPeers  []string
	meshListeners map[int]*guardedListener
	listenersMu   sync.Mutex

	// Control-plane datagram correlation on the shared WireGuard socket.
	stunMu       sync.Mutex
	stunWaiters  map[[12]byte]chan *stun.ReflexiveAddress
	punchMu      sync.Mutex
	punchWaiters map[string]chan struct{}

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewDaemon initializes a new node daemon.
func NewDaemon(cfg *config.NodeConfig) (*Daemon, error) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate WireGuard keypair: %w", err)
	}

	var tunDev tun.Device
	if cfg.InterfaceMode == "netstack" {
		tunDev = tun.NewMemoryDevice(cfg.InterfaceName, cfg.MTU)
	} else {
		tunDev, err = tun.CreateTUN(cfg.InterfaceName, cfg.MTU)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize TUN device: %w", err)
		}
		// Bring the link up before creating the WireGuard device. Otherwise the
		// kernel reports the TUN as down and wireguard-go closes its bind.
		if err := netcfg.EnsureLinkUp(cfg.InterfaceName, cfg.MTU); err != nil {
			slog.Warn("Could not bring overlay interface up (data plane may be limited)", "interface", cfg.InterfaceName, "error", err)
		}
	}

	// One UDP socket is shared by WireGuard, STUN, disco, and hole punching so
	// that the reflexive port peers learn is the port WireGuard receives on.
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: cfg.ListenPort})
	if err != nil {
		_ = tunDev.Close()
		return nil, fmt.Errorf("failed to bind shared UDP socket: %w", err)
	}

	d := &Daemon{
		cfg:           cfg,
		keyPair:       kp,
		peers:         make(map[string]core.Node),
		tunDev:        tunDev,
		udpConn:       udpConn,
		routingTable:  router.NewTable(),
		tunnelClient:  tunnel.NewClient(),
		allowedPorts:  cfg.AllowedInboundPorts,
		defaultDeny:   cfg.DefaultDeny,
		meshListeners: make(map[int]*guardedListener),
		stunWaiters:   make(map[[12]byte]chan *stun.ReflexiveAddress),
		punchWaiters:  make(map[string]chan struct{}),
	}

	d.httpClient = &http.Client{
		Timeout:   10 * time.Second,
		Transport: controlauth.NewBearerTransport(nil, cfg.PlaneEndpoint, d.token.Get),
	}

	wgMgr, err := wireguard.NewManager(cfg.InterfaceName,
		wireguard.WithTunDevice(tunDev),
		wireguard.WithPrivateKey(kp.PrivateKey),
		wireguard.WithSharedSocket(udpConn, d.handleControlPacket),
	)
	if err != nil {
		_ = udpConn.Close()
		_ = tunDev.Close()
		return nil, fmt.Errorf("failed to initialize WireGuard manager: %w", err)
	}

	d.wgManager = wgMgr
	d.discoEngine = disco.NewEngine(kp, udpConn)
	return d, nil
}

// Start boots the client daemon, enrolls with the control plane, and establishes mesh connectivity.
func (d *Daemon) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	d.cancel = cancel

	// 1. The shared UDP socket (bound in NewDaemon) is driven by the WireGuard
	// bind's single read loop, which dispatches non-WireGuard datagrams to
	// handleControlPacket.
	slog.Info("ZRO Node agent initialized", "pubkey", d.keyPair.PublicKey, "local_udp", d.udpConn.LocalAddr().String())

	// Connect gRPC client if plane transport is set to grpc
	if strings.EqualFold(d.cfg.PlaneTransport, "grpc") {
		grpcTarget := d.cfg.PlaneEndpoint
		if d.cfg.GRPCEndpoint != "" {
			grpcTarget = d.cfg.GRPCEndpoint
		}
		gc, err := controlgrpc.DialPlane(d.cfg.PlaneEndpoint, d.cfg.PlaneGRPC, d.token.Get)
		if err == nil {
			d.grpcClient = gc
			slog.Info("ZRO Node connected to Control Plane via gRPC", "target", grpcTarget)
		} else {
			slog.Warn("Failed to initialize gRPC client, falling back to REST", "error", err)
		}
	}

	// 2. Section 5.1 Step 2: Fetch PoP catalog and conduct parallel UDP RTT probes
	pops, _ := d.fetchPoPs(ctx)
	probes, bestPoP := d.probePoPs(ctx, pops)

	// Discover our reflexive endpoint on the shared socket, not on the
	// short-lived probe socket. Only then does the advertised address match
	// the NAT mapping WireGuard receives on.
	var endpoints []string
	if bestPoP != "" {
		if reflexive, err := d.discoverReflexive(bestPoP, 2*time.Second); err == nil && reflexive != nil {
			endpoints = append(endpoints, reflexive.String())
		} else if err != nil {
			slog.Warn("Could not discover reflexive endpoint on shared socket", "stun_server", bestPoP, "error", err)
		}
	}

	// 3. Section 5.1 Steps 3-4: Enroll with Control Plane and report probe telemetry for Smart Delegation
	var enrollResp server.EnrollResponse

	if d.grpcClient != nil {
		var protoProbes []*v1.LatencyProbe
		for _, p := range probes {
			protoProbes = append(protoProbes, &v1.LatencyProbe{
				PopCode:    p.PoPCode,
				RttNs:      p.RTT.Nanoseconds(),
				PacketLoss: p.PacketLoss,
			})
		}

		gResp, err := d.grpcClient.Enroll(ctx, &v1.EnrollRequest{
			Token:        d.cfg.EnrollmentToken,
			PublicKey:    d.keyPair.PublicKey,
			Hostname:     d.cfg.Hostname,
			NodeType:     "peer",
			Tags:         d.cfg.Tags,
			Endpoints:    endpoints,
			Probes:       protoProbes,
			AllowedPorts: d.allowedPorts,
			DefaultDeny:  &d.defaultDeny,
		})
		if err != nil {
			return fmt.Errorf("gRPC enrollment failed: %w", err)
		}

		nodeUUID, _ := uuid.Parse(gResp.NodeId)
		enrollResp = server.EnrollResponse{
			NodeID:      nodeUUID,
			NetworkID:   gResp.NetworkId,
			NodeToken:   gResp.NodeToken,
			OverlayIPv4: gResp.OverlayIpv4,
			OverlayIPv6: gResp.OverlayIpv6,
		}
		if gResp.PrimaryPop != nil {
			enrollResp.PrimaryPoP = core.EdgePoP{
				PoPCode:        gResp.PrimaryPop.PopCode,
				PublicEndpoint: gResp.PrimaryPop.PublicEndpoint,
				PublicKey:      gResp.PrimaryPop.PublicKey,
				Region:         gResp.PrimaryPop.Region,
			}
		}
		if gResp.SecondaryPop != nil {
			sec := core.EdgePoP{
				PoPCode:        gResp.SecondaryPop.PopCode,
				PublicEndpoint: gResp.SecondaryPop.PublicEndpoint,
				PublicKey:      gResp.SecondaryPop.PublicKey,
				Region:         gResp.SecondaryPop.Region,
			}
			enrollResp.SecondaryPoP = &sec
		}
		for _, p := range gResp.Peers {
			enrollResp.Peers = append(enrollResp.Peers, core.Node{
				Hostname:    p.Hostname,
				PublicKey:   p.PublicKey,
				OverlayIPv4: p.OverlayIpv4,
				OverlayIPv6: p.OverlayIpv6,
				Endpoints:   core.StringList(p.Endpoints),
			})
		}
	} else {
		enrollReq := server.EnrollRequest{
			Token:        d.cfg.EnrollmentToken,
			PublicKey:    d.keyPair.PublicKey,
			Hostname:     d.cfg.Hostname,
			NodeType:     core.NodeTypePeer,
			Tags:         core.StringList(d.cfg.Tags),
			Endpoints:    core.StringList(endpoints),
			AllowedPorts: core.StringList(d.allowedPorts),
			DefaultDeny:  &d.defaultDeny,
			Probes:       probes,
		}

		bodyBytes, err := json.Marshal(enrollReq)
		if err != nil {
			return err
		}

		req, err := http.NewRequestWithContext(ctx, "POST", d.cfg.PlaneEndpoint+"/api/v1/enroll", bytes.NewReader(bodyBytes))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := d.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("enrollment request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("enrollment rejected by control plane: status %d", resp.StatusCode)
		}

		if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
			return fmt.Errorf("failed to decode enrollment response: %w", err)
		}
	}

	d.token.Set(enrollResp.NodeToken)
	d.nodeID = enrollResp.NodeID
	d.networkID = enrollResp.NetworkID
	d.overlayIPv4 = enrollResp.OverlayIPv4
	d.overlayIPv6 = enrollResp.OverlayIPv6

	// Program the host so overlay traffic enters the WireGuard interface.
	// netstack mode has no OS interface, so it is skipped there.
	if d.cfg.InterfaceMode != "netstack" {
		if err := netcfg.ConfigureOverlay(d.cfg.InterfaceName, d.overlayIPv4, d.overlayIPv6, d.cfg.MTU); err != nil {
			slog.Warn("Failed to configure overlay interface addresses (data plane may be limited)",
				"interface", d.cfg.InterfaceName, "error", err)
		}
	}

	d.popMu.Lock()
	d.primaryPoP = enrollResp.PrimaryPoP
	d.secondaryPoP = enrollResp.SecondaryPoP
	d.popMu.Unlock()

	slog.Info("Enrolled into overlay mesh",
		"overlay_ipv4", d.overlayIPv4,
		"overlay_ipv6", d.overlayIPv6,
		"delegated_pop", d.primaryPoP.PoPCode,
		"pop_endpoint", d.primaryPoP.PublicEndpoint)

	// 4. Section 5.1 Step 5: Connect to Delegated Primary Edge PoP
	if err := d.connectToEdgePoP(d.primaryPoP); err != nil {
		slog.Warn("Failed to establish primary Edge PoP tunnel", "error", err)
	}

	// 5. Connect to peers (P2P direct with fallback)
	for _, peer := range enrollResp.Peers {
		if peer.PublicKey != d.keyPair.PublicKey {
			d.connectPeer(ctx, peer)
		}
	}

	// 6. Launch background workers (latency probes & local tunnels)
	d.wg.Add(2)
	go d.probeWorker(ctx)
	go d.tunnelWorker(ctx)

	return nil
}

func (d *Daemon) fetchPoPs(ctx context.Context) ([]core.EdgePoP, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", d.cfg.PlaneEndpoint+"/api/v1/pops", nil)
	if err != nil {
		return nil, err
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var pops []core.EdgePoP
	if err := json.NewDecoder(resp.Body).Decode(&pops); err != nil {
		return nil, err
	}
	return pops, nil
}

func (d *Daemon) probePoPs(ctx context.Context, pops []core.EdgePoP) ([]core.LatencySample, string) {
	if len(pops) == 0 {
		return nil, ""
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var samples []core.LatencySample
	var bestPoP string
	bestRTT := time.Duration(1<<62 - 1)

	for _, pop := range pops {
		if pop.PublicEndpoint == "" {
			continue
		}
		wg.Add(1)
		go func(p core.EdgePoP) {
			defer wg.Done()
			rtt, _, err := stun.ProbeEndpoint(p.PublicEndpoint, 1200*time.Millisecond)
			mu.Lock()
			defer mu.Unlock()

			if err == nil {
				samples = append(samples, core.LatencySample{
					PoPCode:    p.PoPCode,
					RTT:        rtt,
					PacketLoss: 0.0,
					Timestamp:  time.Now(),
				})
				if rtt < bestRTT {
					bestRTT = rtt
					bestPoP = p.PublicEndpoint
				}
			} else {
				// Failed probe penalty
				samples = append(samples, core.LatencySample{
					PoPCode:    p.PoPCode,
					RTT:        500 * time.Millisecond,
					PacketLoss: 1.0,
					Timestamp:  time.Now(),
				})
			}
		}(pop)
	}

	wg.Wait()
	return samples, bestPoP
}

// discoverReflexive performs a STUN binding exchange on the shared socket. It
// registers a waiter keyed by transaction ID; the WireGuard bind's read loop
// delivers the response through handleControlPacket.
func (d *Daemon) discoverReflexive(serverAddr string, timeout time.Duration) (*stun.ReflexiveAddress, error) {
	srv, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve STUN server: %w", err)
	}

	req, txID, err := stun.NewBindingRequest()
	if err != nil {
		return nil, err
	}

	respCh := make(chan *stun.ReflexiveAddress, 1)
	d.stunMu.Lock()
	d.stunWaiters[txID] = respCh
	d.stunMu.Unlock()
	defer func() {
		d.stunMu.Lock()
		delete(d.stunWaiters, txID)
		d.stunMu.Unlock()
	}()

	if _, err := d.udpConn.WriteToUDP(req, srv); err != nil {
		return nil, fmt.Errorf("failed to send STUN request: %w", err)
	}

	deadline := time.Now().Add(timeout)
	for attempt := 0; attempt < 3; attempt++ {
		wait := time.Until(deadline)
		if wait <= 0 {
			break
		}
		if remainingAttempts := 3 - attempt; wait > timeout/time.Duration(remainingAttempts) {
			wait = timeout / time.Duration(remainingAttempts)
		}
		select {
		case reflexive := <-respCh:
			return reflexive, nil
		case <-time.After(wait):
			if time.Now().After(deadline) {
				break
			}
			if _, err := d.udpConn.WriteToUDP(req, srv); err != nil {
				return nil, fmt.Errorf("failed to send STUN request: %w", err)
			}
		}
	}
	return nil, errors.New("STUN reflexive discovery timed out")
}

// handleControlPacket is invoked by the shared WireGuard bind for every
// datagram that is not a WireGuard protocol packet.
func (d *Daemon) handleControlPacket(packet []byte, remoteAddr *net.UDPAddr) {
	// P2P hole punching: answer pings and wake the matching waiter on pongs.
	if puncher.IsPing(packet) {
		_, _ = d.udpConn.WriteToUDP(puncher.MagicPong, remoteAddr)
		return
	}
	if puncher.IsPong(packet) {
		d.signalPunch(remoteAddr)
		return
	}

	// STUN responses for a pending reflexive discovery.
	if stun.IsBindingResponse(packet) {
		if len(packet) < 20 {
			return
		}
		var txID [12]byte
		copy(txID[:], packet[8:20])
		d.stunMu.Lock()
		waiter := d.stunWaiters[txID]
		d.stunMu.Unlock()
		if waiter == nil {
			return
		}
		reflexive, err := stun.ParseResponse(packet, txID[:])
		if err != nil {
			return
		}
		select {
		case waiter <- reflexive:
		default:
		}
		return
	}

	// Incoming STUN binding requests are answered directly (nodes also act as
	// small STUN reflectors for peers on the same overlay).
	if stun.IsBindingRequest(packet) {
		_ = stun.ServeSTUN(d.udpConn, packet, remoteAddr)
		return
	}

	// Disco protocol messages.
	if d.discoEngine != nil {
		_, _ = d.discoEngine.HandlePacket(packet, remoteAddr)
	}
}

func (d *Daemon) signalPunch(from *net.UDPAddr) {
	key := from.String()
	ipKey := from.IP.String()

	d.punchMu.Lock()
	defer d.punchMu.Unlock()
	for candidate, waiter := range d.punchWaiters {
		if candidate == key || candidate == ipKey {
			select {
			case waiter <- struct{}{}:
			default:
			}
		}
	}
}

// punchTo opens a NAT mapping with a peer by sending periodic pings and
// waiting for a pong on the shared socket.
func (d *Daemon) punchTo(ctx context.Context, remote string, timeout time.Duration) (bool, time.Duration) {
	addr, err := net.ResolveUDPAddr("udp", remote)
	if err != nil {
		return false, 0
	}

	key := addr.String()
	ipKey := addr.IP.String()
	waiter := make(chan struct{}, 1)

	d.punchMu.Lock()
	d.punchWaiters[key] = waiter
	d.punchWaiters[ipKey] = waiter
	d.punchMu.Unlock()
	defer func() {
		d.punchMu.Lock()
		if d.punchWaiters[key] == waiter {
			delete(d.punchWaiters, key)
		}
		if d.punchWaiters[ipKey] == waiter {
			delete(d.punchWaiters, ipKey)
		}
		d.punchMu.Unlock()
	}()

	start := time.Now()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	// Send the first ping immediately; optimize the common case.
	_, _ = d.udpConn.WriteToUDP(puncher.MagicPing, addr)

	for {
		select {
		case <-ctx.Done():
			return false, 0
		case <-time.After(timeout):
			return false, 0
		case <-waiter:
			return true, time.Since(start)
		case <-ticker.C:
			_, _ = d.udpConn.WriteToUDP(puncher.MagicPing, addr)
		}
	}
}

// Stop terminates the node daemon.
func (d *Daemon) Stop() error {
	if d.cancel != nil {
		d.cancel()
	}
	// Close WireGuard first: it owns the read loop on the shared socket.
	if d.wgManager != nil {
		_ = d.wgManager.Close()
	}
	if d.udpConn != nil {
		_ = d.udpConn.Close()
	}
	if d.tunDev != nil {
		_ = d.tunDev.Close()
	}
	if d.derpClient != nil {
		_ = d.derpClient.Close()
	}
	if d.grpcClient != nil {
		_ = d.grpcClient.Close()
	}
	d.wg.Wait()
	return nil
}

func (d *Daemon) connectToEdgePoP(pop core.EdgePoP) error {
	if pop.PublicKey == "" {
		return nil
	}

	// Establish DERP encrypted packet relay client connection if endpoint is reachable
	if pop.PublicEndpoint != "" && d.derpClient == nil {
		go func() {
			dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer dialCancel()
			dc, err := derp.ConnectDERP(dialCtx, pop.PublicEndpoint, d.keyPair)
			if err == nil {
				d.derpClient = dc
				slog.Info("Connected to Edge DERP relay fallback", "pop", pop.PoPCode, "endpoint", pop.PublicEndpoint)
			}
		}()
	}

	// Route all private overlay traffic through primary PoP as default relay
	return d.wgManager.ApplyPeer(wireguard.PeerConfig{
		PublicKey:           pop.PublicKey,
		Endpoint:            pop.PublicEndpoint,
		AllowedIPs:          []string{"100.64.0.0/10", "fd00:cafe::/64"},
		PersistentKeepalive: 25 * time.Second,
	})
}

// DiscoverAndConnectPeer implements Section 5 Packet Flow & Smart Routing:
// 1. Requests P2P discovery coordinates from Control Plane (Target Reflexive Addrs & delegated PoP)
// 2. Attempts simultaneous direct UDP hole punch (RFC 5128 / ICE style)
// 3. If direct P2P succeeds -> Sets WireGuard direct peer path with zero relay latency
// 4. If blocked by Symmetric NAT -> Falls back to Edge Backbone Mesh relay transit
func (d *Daemon) DiscoverAndConnectPeer(ctx context.Context, targetOverlayIP string) (*router.RouteTarget, error) {
	// 1. Request P2P discovery from Control Plane
	var endpoints []string
	if d.udpConn != nil {
		endpoints = append(endpoints, d.udpConn.LocalAddr().String())
	}

	discResp, err := d.discoverPeer(ctx, server.P2PDiscoverRequest{
		InitiatorNodeID:    d.nodeID,
		TargetOverlayIP:    targetOverlayIP,
		InitiatorEndpoints: core.StringList(endpoints),
	})
	if err != nil {
		return nil, err
	}

	// 2. Attempt direct P2P Hole Punching if enabled and target endpoints exist
	var directEndpoint string
	if d.cfg.EnableP2P && len(discResp.TargetEndpoints) > 0 {
		for _, ep := range discResp.TargetEndpoints {
			ok, rtt := d.punchTo(ctx, ep, 500*time.Millisecond)
			if ok {
				directEndpoint = ep
				slog.Info("Direct P2P tunnel established with zero relay latency",
					"target", discResp.TargetHostname,
					"endpoint", ep,
					"rtt", rtt)
				break
			}
		}
	}

	// 3. Fallback logic according to Section 5 sequence diagram
	var routeTarget router.RouteTarget
	if directEndpoint != "" {
		// Direct WireGuard P2P
		_ = d.wgManager.ApplyPeer(wireguard.PeerConfig{
			PublicKey:           discResp.TargetPublicKey,
			Endpoint:            directEndpoint,
			AllowedIPs:          []string{discResp.TargetOverlayIPv4 + "/32"},
			PersistentKeepalive: 20 * time.Second,
		})

		routeTarget = router.RouteTarget{
			PublicKey:   discResp.TargetPublicKey,
			Endpoint:    directEndpoint,
			IsDirectP2P: true,
			Metric:      10,
		}
	} else {
		// Blocked by Symmetric NAT: Transit via Edge Backbone Mesh
		d.popMu.RLock()
		primaryPoP := d.primaryPoP
		d.popMu.RUnlock()

		relayEndpoint := primaryPoP.PublicEndpoint
		if relayEndpoint == "" && discResp.PrimaryPoP != nil {
			relayEndpoint = discResp.PrimaryPoP.PublicEndpoint
		}

		slog.Warn("P2P hole punch blocked by symmetric NAT; routing through Edge Backbone Mesh",
			"target", discResp.TargetHostname,
			"primary_pop", primaryPoP.PoPCode)

		_ = d.wgManager.ApplyPeer(wireguard.PeerConfig{
			PublicKey:           discResp.TargetPublicKey,
			Endpoint:            relayEndpoint,
			AllowedIPs:          []string{discResp.TargetOverlayIPv4 + "/32"},
			PersistentKeepalive: 25 * time.Second,
		})

		routeTarget = router.RouteTarget{
			PublicKey:   discResp.TargetPublicKey,
			Endpoint:    relayEndpoint,
			ViaPoPCode:  primaryPoP.PoPCode,
			IsDirectP2P: false,
			Metric:      100,
		}
	}

	d.routingTable.SetRoute(discResp.TargetOverlayIPv4, routeTarget)
	return &routeTarget, nil
}

func (d *Daemon) connectPeer(ctx context.Context, peer core.Node) {
	d.peersMu.Lock()
	d.peers[peer.PublicKey] = peer
	d.peersMu.Unlock()

	if d.cfg.InterfaceMode != "netstack" {
		if peer.OverlayIPv4 != "" {
			if err := netcfg.AddHostRoute(d.cfg.InterfaceName, peer.OverlayIPv4); err != nil {
				slog.Debug("Failed to add overlay route", "peer", peer.OverlayIPv4, "error", err)
			}
		}
		if peer.OverlayIPv6 != "" {
			if err := netcfg.AddHostRoute(d.cfg.InterfaceName, peer.OverlayIPv6); err != nil {
				slog.Debug("Failed to add overlay route", "peer", peer.OverlayIPv6, "error", err)
			}
		}
	}

	_, _ = d.DiscoverAndConnectPeer(ctx, peer.OverlayIPv4)
}

func (d *Daemon) probeWorker(ctx context.Context) {
	defer d.wg.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	var consecutiveFails int

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.popMu.RLock()
			primary := d.primaryPoP
			secondary := d.secondaryPoP
			d.popMu.RUnlock()

			if primary.PublicEndpoint == "" {
				continue
			}

			// Probe primary Edge PoP
			rtt, _, err := stun.ProbeEndpoint(primary.PublicEndpoint, 1*time.Second)
			loss := 0.0
			if err != nil {
				loss = 1.0
				rtt = 500 * time.Millisecond
				consecutiveFails++
			} else {
				consecutiveFails = 0
			}

			// Report probe telemetry to Control Plane
			sample := core.LatencySample{
				NodeID:     d.nodeID,
				PoPCode:    primary.PoPCode,
				RTT:        rtt,
				PacketLoss: loss,
				Timestamp:  time.Now(),
			}

			d.reportProbe(ctx, sample)

			// Failover to secondary Edge PoP if primary is unreachable (consecutive failures >= 2)
			if consecutiveFails >= 2 && secondary != nil && secondary.PublicEndpoint != "" {
				slog.Warn("Primary Edge PoP degraded/unreachable, failing over to secondary Edge PoP",
					"old_primary", primary.PoPCode,
					"new_primary", secondary.PoPCode)

				d.popMu.Lock()
				d.primaryPoP = *secondary
				d.secondaryPoP = &primary
				d.popMu.Unlock()

				_ = d.connectToEdgePoP(*secondary)
				consecutiveFails = 0
			}
		}
	}
}

func (d *Daemon) tunnelWorker(ctx context.Context) {
	defer d.wg.Done()

	// Register Cloudflared-style exposed local services with the Control Plane and local tunnel engine
	for _, tunCfg := range d.cfg.Tunnels {
		_ = d.tunnelClient.ExposeService(tunnel.IngressDefinition{
			NodeID:         d.nodeID,
			Name:           tunCfg.Name,
			LocalAddress:   tunCfg.LocalAddress,
			PublicHostname: tunCfg.PublicHostname,
			Protocol:       tunCfg.Protocol,
		})

		t := core.Tunnel{
			NodeID:         d.nodeID,
			Name:           tunCfg.Name,
			LocalAddress:   tunCfg.LocalAddress,
			PublicHostname: tunCfg.PublicHostname,
			Protocol:       tunCfg.Protocol,
		}

		if err := d.registerTunnel(ctx, t); err != nil {
			slog.Warn("Failed to register tunnel with the control plane", "name", tunCfg.Name, "error", err)
			continue
		}
		slog.Info("Exposed local service tunnel", "name", tunCfg.Name, "hostname", tunCfg.PublicHostname, "local", tunCfg.LocalAddress)
	}
}

// discoverPeer asks the plane for a peer's coordinates over gRPC when it is
// configured, otherwise over REST.
func (d *Daemon) discoverPeer(ctx context.Context, req server.P2PDiscoverRequest) (*server.P2PDiscoverResponse, error) {
	if d.grpcClient != nil {
		g, err := d.grpcClient.DiscoverP2P(ctx, &v1.P2PDiscoverRequest{
			InitiatorNodeId:    req.InitiatorNodeID.String(),
			TargetOverlayIp:    req.TargetOverlayIP,
			InitiatorEndpoints: req.InitiatorEndpoints,
		})
		if err != nil {
			return nil, fmt.Errorf("p2p discovery rejected: %w", err)
		}
		targetID, _ := uuid.Parse(g.TargetNodeId)
		out := &server.P2PDiscoverResponse{
			TargetNodeID:      targetID,
			TargetHostname:    g.TargetHostname,
			TargetPublicKey:   g.TargetPublicKey,
			TargetOverlayIPv4: g.TargetOverlayIpv4,
			TargetOverlayIPv6: g.TargetOverlayIpv6,
			TargetEndpoints:   core.StringList(g.TargetEndpoints),
		}
		if g.PrimaryPop != nil {
			out.PrimaryPoP = &core.EdgePoP{PoPCode: g.PrimaryPop.PopCode, PublicEndpoint: g.PrimaryPop.PublicEndpoint, PublicKey: g.PrimaryPop.PublicKey, Region: g.PrimaryPop.Region}
		}
		return out, nil
	}

	var out server.P2PDiscoverResponse
	if err := d.postPlane(ctx, "/api/v1/p2p/discover", req, http.StatusOK, &out); err != nil {
		return nil, fmt.Errorf("p2p discovery failed: %w", err)
	}
	return &out, nil
}

// reportProbe sends a latency sample to the plane (best effort).
func (d *Daemon) reportProbe(ctx context.Context, sample core.LatencySample) {
	if d.grpcClient != nil {
		_, _ = d.grpcClient.ReportProbes(ctx, &v1.ProbeReportRequest{
			NodeId: d.nodeID.String(), PopCode: sample.PoPCode, RttNs: sample.RTT.Nanoseconds(), PacketLoss: sample.PacketLoss,
		})
		return
	}
	_ = d.postPlane(ctx, "/api/v1/probes", sample, http.StatusAccepted, nil)
}

// registerTunnel registers an exposed service with the plane.
func (d *Daemon) registerTunnel(ctx context.Context, t core.Tunnel) error {
	if d.grpcClient != nil {
		_, err := d.grpcClient.RegisterTunnel(ctx, &v1.RegisterTunnelRequest{
			Name: t.Name, LocalAddress: t.LocalAddress, PublicHostname: t.PublicHostname, Protocol: t.Protocol,
		})
		return err
	}
	return d.postPlane(ctx, "/api/v1/tunnels", t, http.StatusCreated, nil)
}

// postPlane POSTs JSON to the plane over REST, expecting wantStatus, and
// decodes the response into out when it is non-nil.
func (d *Daemon) postPlane(ctx context.Context, path string, body any, wantStatus int, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.cfg.PlaneEndpoint+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// OverlayIPv4 returns the assigned static overlay IPv4.
func (d *Daemon) OverlayIPv4() string {
	return d.overlayIPv4
}

// SetOverlayIP sets the overlay IPv4 (used during enrollment or testing).
func (d *Daemon) SetOverlayIP(ip string) {
	d.overlayIPv4 = ip
}

// PublicKey returns the node's WireGuard public key.
func (d *Daemon) PublicKey() string {
	return d.keyPair.PublicKey
}

// globalMeshRegistry tracks registered overlay listeners across the node network.
var globalMeshRegistry = sync.Map{} // "overlayIP:port" -> *guardedListener

// SetInboundPolicy updates the node's zero-trust inbound firewall policy.
func (d *Daemon) SetInboundPolicy(allowedPorts []string, defaultDeny bool, allowedPeers []string) {
	d.policyMu.Lock()
	defer d.policyMu.Unlock()
	d.allowedPorts = allowedPorts
	d.defaultDeny = defaultDeny
	d.allowedPeers = allowedPeers
	slog.Info("Zero-trust inbound policy updated", "hostname", d.cfg.Hostname, "allowed_ports", allowedPorts, "default_deny", defaultDeny)
}

// AllowPort adds an allowed port/protocol rule to the node's inbound firewall (e.g. "5432/tcp" or "5432").
func (d *Daemon) AllowPort(portProto string) {
	d.policyMu.Lock()
	defer d.policyMu.Unlock()
	for _, p := range d.allowedPorts {
		if p == portProto {
			return
		}
	}
	d.allowedPorts = append(d.allowedPorts, portProto)
	slog.Info("Allowed inbound port", "hostname", d.cfg.Hostname, "port", portProto)
}

// DenyPort removes an allowed port rule from the node's inbound firewall.
func (d *Daemon) DenyPort(portProto string) {
	d.policyMu.Lock()
	defer d.policyMu.Unlock()
	var updated []string
	for _, p := range d.allowedPorts {
		if p != portProto {
			updated = append(updated, p)
		}
	}
	d.allowedPorts = updated
	slog.Info("Denying inbound port", "hostname", d.cfg.Hostname, "port", portProto)
}

// IsTrafficAllowed evaluates if incoming traffic from srcIP to localPort on protocol is permitted.
// If defaultDeny is enabled, all ports are denied unless explicitly allowed.
func (d *Daemon) IsTrafficAllowed(srcIP string, protocol string, destPort int) bool {
	d.policyMu.RLock()
	allowedPorts := d.allowedPorts
	defaultDeny := d.defaultDeny
	allowedPeers := d.allowedPeers
	d.policyMu.RUnlock()

	// 1. If allowedPeers is specified, verify srcIP
	if len(allowedPeers) > 0 {
		peerAllowed := false
		for _, peer := range allowedPeers {
			if peer == "*" || peer == srcIP {
				peerAllowed = true
				break
			}
		}
		if !peerAllowed {
			return false
		}
	}

	// 2. Check if port & protocol is in allowedPorts list
	for _, ap := range allowedPorts {
		ap = strings.TrimSpace(ap)
		if ap == "*" {
			return true
		}

		parts := strings.Split(ap, "/")
		portPart := parts[0]
		protoPart := "*"
		if len(parts) > 1 {
			protoPart = parts[1]
		}

		if protoPart == "*" || strings.EqualFold(protoPart, protocol) {
			p, err := strconv.Atoi(portPart)
			if err == nil && p == destPort {
				return true
			}
		}
	}

	// 3. If zero-trust default deny is active, deny any unlisted port
	if defaultDeny {
		return false
	}

	return true
}

// MeshAddr represents a network address in the private overlay space.
type MeshAddr struct {
	IP   string
	Port int
	Net  string
}

func (a *MeshAddr) Network() string {
	if a.Net != "" {
		return a.Net
	}
	return "mesh"
}

func (a *MeshAddr) String() string {
	return net.JoinHostPort(a.IP, strconv.Itoa(a.Port))
}

type meshPipeConn struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *meshPipeConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *meshPipeConn) RemoteAddr() net.Addr { return c.remoteAddr }

type guardedListener struct {
	daemon     *Daemon
	targetPort int
	protocol   string
	overlayIP  string
	connCh     chan net.Conn
	closed     chan struct{}
	closeOnce  sync.Once
}

func (g *guardedListener) Accept() (net.Conn, error) {
	select {
	case <-g.closed:
		return nil, net.ErrClosed
	case conn, ok := <-g.connCh:
		if !ok {
			return nil, net.ErrClosed
		}
		return conn, nil
	}
}

func (g *guardedListener) Close() error {
	g.closeOnce.Do(func() {
		close(g.closed)
		key := fmt.Sprintf("%s:%d", g.overlayIP, g.targetPort)
		globalMeshRegistry.Delete(key)
	})
	return nil
}

func (g *guardedListener) Addr() net.Addr {
	return &MeshAddr{
		IP:   g.overlayIP,
		Port: g.targetPort,
		Net:  g.protocol,
	}
}

// ListenMesh opens a network listener guarded by the node's Zero-Trust Inbound Firewall.
// Unauthorized connections from nodes to unallowed ports are dropped/rejected.
func (d *Daemon) ListenMesh(ctx context.Context, network string, port int) (net.Listener, error) {
	overlayIP := d.overlayIPv4
	if overlayIP == "" {
		overlayIP = "127.0.0.1"
	}

	gl := &guardedListener{
		daemon:     d,
		targetPort: port,
		protocol:   network,
		overlayIP:  overlayIP,
		connCh:     make(chan net.Conn, 128),
		closed:     make(chan struct{}),
	}

	d.listenersMu.Lock()
	d.meshListeners[port] = gl
	d.listenersMu.Unlock()

	regKey := fmt.Sprintf("%s:%d", overlayIP, port)
	globalMeshRegistry.Store(regKey, gl)
	slog.Info("Bound Zero-Trust Mesh Listener", "overlay_ip", overlayIP, "port", port, "protocol", network)

	return gl, nil
}

// DialMesh establishes a connection to a remote node's overlay IP across the mesh.
// Example: d.DialMesh(ctx, "tcp", "100.64.0.10:5432")
func (d *Daemon) DialMesh(ctx context.Context, network, address string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid mesh address: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	// 1. Resolve and connect peer if not already connected
	if host != d.overlayIPv4 && host != "127.0.0.1" {
		_, _ = d.DiscoverAndConnectPeer(ctx, host)
	}

	srcIP := d.overlayIPv4
	if srcIP == "" {
		srcIP = "127.0.0.1"
	}

	// 2. Check virtual mesh registry for target listener
	regKey := fmt.Sprintf("%s:%d", host, port)
	if val, ok := globalMeshRegistry.Load(regKey); ok {
		targetLn := val.(*guardedListener)

		// Evaluate target node's Zero-Trust Inbound Firewall!
		if !targetLn.daemon.IsTrafficAllowed(srcIP, network, port) {
			slog.Warn("Zero-Trust Inbound Firewall rejected connection",
				"src", srcIP,
				"dst", address,
				"reason", "default_deny_all_or_unauthorized_port")
			return nil, fmt.Errorf("connection to %s rejected: access denied by destination node zero-trust policy", address)
		}

		clientEnd, serverEnd := net.Pipe()

		clientConn := &meshPipeConn{
			Conn:       clientEnd,
			localAddr:  &MeshAddr{IP: srcIP, Port: 51820, Net: network},
			remoteAddr: &MeshAddr{IP: host, Port: port, Net: network},
		}

		serverConn := &meshPipeConn{
			Conn:       serverEnd,
			localAddr:  &MeshAddr{IP: host, Port: port, Net: network},
			remoteAddr: &MeshAddr{IP: srcIP, Port: 51820, Net: network},
		}

		select {
		case targetLn.connCh <- serverConn:
			return clientConn, nil
		case <-ctx.Done():
			_ = clientConn.Close()
			_ = serverConn.Close()
			return nil, ctx.Err()
		case <-targetLn.closed:
			_ = clientConn.Close()
			_ = serverConn.Close()
			return nil, fmt.Errorf("target service %s is closed", address)
		}
	}

	// 3. Fallback to direct network socket dialer
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}
