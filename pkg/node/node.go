package node

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cubis/zro/pkg/config"
	"github.com/cubis/zro/pkg/control/server"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/crypto"
	"github.com/cubis/zro/pkg/dataplane/derp"
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

	// Zero-Trust Inbound Firewall & Mesh Listeners
	policyMu      sync.RWMutex
	allowedPorts  []string // e.g. ["5432/tcp"]
	defaultDeny   bool     // default true for zero-trust
	allowedPeers  []string
	meshListeners map[int]*guardedListener
	listenersMu   sync.Mutex

	cancel       context.CancelFunc
	wg           sync.WaitGroup
}

// NewDaemon initializes a new node daemon.
func NewDaemon(cfg *config.NodeConfig) (*Daemon, error) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate WireGuard keypair: %w", err)
	}

	wgMgr, err := wireguard.NewManager(cfg.InterfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize WireGuard manager: %w", err)
	}

	tunDev, err := tun.CreateTUN(cfg.InterfaceName, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize TUN device: %w", err)
	}

	return &Daemon{
		cfg:           cfg,
		keyPair:       kp,
		peers:         make(map[string]core.Node),
		tunDev:        tunDev,
		wgManager:     wgMgr,
		routingTable:  router.NewTable(),
		tunnelClient:  tunnel.NewClient(),
		httpClient:    &http.Client{Timeout: 10 * time.Second},
		allowedPorts:  cfg.AllowedInboundPorts,
		defaultDeny:   cfg.DefaultDeny,
		meshListeners: make(map[int]*guardedListener),
	}, nil
}

// Start boots the client daemon, enrolls with the control plane, and establishes mesh connectivity.
func (d *Daemon) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	d.cancel = cancel

	// 1. Bind local UDP listener for STUN, Disco, and WireGuard peering
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return fmt.Errorf("failed to bind UDP socket: %w", err)
	}
	d.udpConn = udpConn
	d.discoEngine = disco.NewEngine(d.keyPair, udpConn)

	slog.Info("ZRO Node agent initialized", "pubkey", d.keyPair.PublicKey, "local_udp", udpConn.LocalAddr().String())

	// Launch UDP packet listener for incoming STUN, Disco, and P2P hole punch packets
	d.wg.Add(1)
	go d.udpPacketListener(ctx)

	// 2. Section 5.1 Step 2: Fetch PoP catalog and conduct parallel UDP RTT probes
	pops, _ := d.fetchPoPs(ctx)
	probes, bestReflexive := d.probePoPs(ctx, pops)

	var endpoints []string
	if bestReflexive != "" {
		endpoints = append(endpoints, bestReflexive)
	}

	// 3. Section 5.1 Steps 3-4: Enroll with Control Plane and report probe telemetry for Smart Delegation
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

	var enrollResp server.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return fmt.Errorf("failed to decode enrollment response: %w", err)
	}

	d.nodeID = enrollResp.NodeID
	d.networkID = enrollResp.NetworkID
	d.overlayIPv4 = enrollResp.OverlayIPv4
	d.overlayIPv6 = enrollResp.OverlayIPv6

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
	var bestReflexive string
	bestRTT := time.Duration(1<<62 - 1)

	for _, pop := range pops {
		if pop.PublicEndpoint == "" {
			continue
		}
		wg.Add(1)
		go func(p core.EdgePoP) {
			defer wg.Done()
			rtt, refAddr, err := stun.ProbeEndpoint(p.PublicEndpoint, 1200*time.Millisecond)
			mu.Lock()
			defer mu.Unlock()

			if err == nil {
				samples = append(samples, core.LatencySample{
					PoPCode:    p.PoPCode,
					RTT:        rtt,
					PacketLoss: 0.0,
					Timestamp:  time.Now(),
				})
				if rtt < bestRTT && refAddr != nil {
					bestRTT = rtt
					bestReflexive = refAddr.String()
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
	return samples, bestReflexive
}

func (d *Daemon) udpPacketListener(ctx context.Context) {
	defer d.wg.Done()
	buf := make([]byte, 2048)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			_ = d.udpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, remoteAddr, err := d.udpConn.ReadFromUDP(buf)
			if err != nil {
				continue
			}

			packet := buf[:n]

			// Handle P2P Hole Punching Pings
			if bytes.Equal(packet, puncher.MagicPing) {
				_, _ = d.udpConn.WriteToUDP(puncher.MagicPong, remoteAddr)
				continue
			}

			// Handle STUN queries
			if len(packet) >= 20 {
				_ = stun.ServeSTUN(d.udpConn, packet, remoteAddr)
			}

			// Handle Disco protocol messages
			if d.discoEngine != nil {
				_, _ = d.discoEngine.HandlePacket(packet, remoteAddr)
			}
		}
	}
}

// Stop terminates the node daemon.
func (d *Daemon) Stop() error {
	if d.cancel != nil {
		d.cancel()
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
	if d.wgManager != nil {
		_ = d.wgManager.Close()
	}
	d.wg.Wait()
	return nil
}

func (d *Daemon) connectToEdgePoP(pop core.EdgePoP) error {
	if pop.PublicKey == "" {
		return nil
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

	discReq := server.P2PDiscoverRequest{
		InitiatorNodeID:    d.nodeID,
		TargetOverlayIP:    targetOverlayIP,
		InitiatorEndpoints: core.StringList(endpoints),
	}

	body, err := json.Marshal(discReq)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", d.cfg.PlaneEndpoint+"/api/v1/p2p/discover", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("p2p discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("p2p discovery rejected: status %d", resp.StatusCode)
	}

	var discResp server.P2PDiscoverResponse
	if err := json.NewDecoder(resp.Body).Decode(&discResp); err != nil {
		return nil, err
	}

	// 2. Attempt direct P2P Hole Punching if enabled and target endpoints exist
	var directEndpoint string
	if d.cfg.EnableP2P && len(discResp.TargetEndpoints) > 0 {
		for _, ep := range discResp.TargetEndpoints {
			punchRes, err := puncher.Punch(ctx, d.udpConn, ep, 500*time.Millisecond)
			if err == nil && punchRes.Success {
				directEndpoint = ep
				slog.Info("Direct P2P tunnel established with zero relay latency",
					"target", discResp.TargetHostname,
					"endpoint", ep,
					"rtt", punchRes.RTT)
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

			body, _ := json.Marshal(sample)
			req, err := http.NewRequestWithContext(ctx, "POST", d.cfg.PlaneEndpoint+"/api/v1/probes", bytes.NewReader(body))
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
				res, err := d.httpClient.Do(req)
				if err == nil {
					_ = res.Body.Close()
				}
			}

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

		body, _ := json.Marshal(t)
		req, err := http.NewRequestWithContext(ctx, "POST", d.cfg.PlaneEndpoint+"/api/v1/tunnels", bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			res, err := d.httpClient.Do(req)
			if err == nil {
				_ = res.Body.Close()
				slog.Info("Exposed local service tunnel", "name", tunCfg.Name, "hostname", tunCfg.PublicHostname, "local", tunCfg.LocalAddress)
			}
		}
	}
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
