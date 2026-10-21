package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	v1 "github.com/cubis/zro/api/proto/v1"
	"github.com/cubis/zro/pkg/config"
	controlgrpc "github.com/cubis/zro/pkg/control/grpc"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/crypto"
	"github.com/cubis/zro/pkg/dataplane/derp"
	"github.com/cubis/zro/pkg/dataplane/netcfg"
	"github.com/cubis/zro/pkg/dataplane/router"
	"github.com/cubis/zro/pkg/dataplane/tun"
	"github.com/cubis/zro/pkg/dataplane/wireguard"
	"github.com/cubis/zro/pkg/netutil"
	"github.com/cubis/zro/pkg/p2p/stun"
	"golang.org/x/net/websocket"
)

// PoPDaemon is the edge data plane daemon running at public PoPs.
type PoPDaemon struct {
	cfg          *config.EdgeConfig
	keyPair      *crypto.KeyPair
	wgManager    *wireguard.Manager
	tunDev       tun.Device
	routingTable *router.Table
	udpListener  *net.UDPConn
	derpServer   *derp.Server
	derpListener net.Listener
	httpClient   *http.Client
	grpcClient   *controlgrpc.Client
	peerCount    int
	peersMu      sync.RWMutex

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewPoPDaemon creates a new Edge Data Plane daemon.
func NewPoPDaemon(cfg *config.EdgeConfig) (*PoPDaemon, error) {
	var kp *crypto.KeyPair
	var err error

	if cfg.WireGuardPrivateKey != "" {
		pub, err := crypto.DerivePublicKey(cfg.WireGuardPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("invalid wireguard private key: %w", err)
		}
		kp = &crypto.KeyPair{
			PrivateKey: cfg.WireGuardPrivateKey,
			PublicKey:  pub,
		}
	} else {
		kp, err = crypto.GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate keypair: %w", err)
		}
	}

	iface := cfg.InterfaceName
	if iface == "" {
		iface = "zro-edge"
	}
	if cfg.MTU <= 0 {
		cfg.MTU = 1420
	}
	cfg.InterfaceName = iface

	tunDev, err := tun.CreateTUN(iface, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize edge TUN device: %w", err)
	}
	if err := netcfg.EnsureLinkUp(iface, cfg.MTU); err != nil {
		slog.Warn("Could not bring edge TUN up (relay may be limited)", "interface", iface, "error", err)
	}

	// The shared socket is owned by the WireGuard bind, which also answers STUN
	// requests. This keeps the advertised PoP endpoint on the same NAT mapping.
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: cfg.ListenPort})
	if err != nil {
		_ = tunDev.Close()
		return nil, fmt.Errorf("failed to bind edge UDP socket: %w", err)
	}

	e := &PoPDaemon{
		cfg:          cfg,
		keyPair:      kp,
		tunDev:       tunDev,
		udpListener:  udpConn,
		routingTable: router.NewTable(),
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}

	wgMgr, err := wireguard.NewManager(iface,
		wireguard.WithTunDevice(tunDev),
		wireguard.WithPrivateKey(kp.PrivateKey),
		wireguard.WithListenPort(cfg.ListenPort),
		wireguard.WithSharedSocket(udpConn, e.handleControlPacket),
	)
	if err != nil {
		_ = udpConn.Close()
		_ = tunDev.Close()
		return nil, fmt.Errorf("failed to init wireguard manager: %w", err)
	}
	e.wgManager = wgMgr

	// Edge PoPs forward overlay traffic between peers. The routes send overlay
	// destinations into the TUN; WireGuard's per-peer AllowedIPs select the
	// outbound tunnel.
	if err := netcfg.EnableForwarding(); err != nil {
		slog.Warn("Could not enable IP forwarding on edge (relay may fail)", "error", err)
	}
	for _, cidr := range []string{"100.64.0.0/10", "fd00:cafe::/64"} {
		if err := netcfg.AddSubnetRoute(iface, cidr); err != nil {
			slog.Warn("Could not add edge overlay route", "cidr", cidr, "error", err)
		}
	}

	// Resolve public or private endpoint dynamically (auto discovery, env override, or internal mode)
	resolvedEndpoint := netutil.ResolveEndpoint(cfg.PublicEndpoint, cfg.ListenPort, cfg.UsePrivateIP)
	slog.Info("Edge endpoint configuration resolved",
		"configured", cfg.PublicEndpoint,
		"resolved", resolvedEndpoint,
		"use_private_ip", cfg.UsePrivateIP)
	cfg.PublicEndpoint = resolvedEndpoint

	return e, nil
}

// handleControlPacket answers STUN on the shared WireGuard socket.
func (e *PoPDaemon) handleControlPacket(packet []byte, remoteAddr *net.UDPAddr) {
	if stun.IsBindingRequest(packet) {
		_ = stun.ServeSTUN(e.udpListener, packet, remoteAddr)
	}
}

// Start launches the Edge PoP listener, STUN responder, and config sync worker.
func (e *PoPDaemon) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel

	listenAddr := fmt.Sprintf("0.0.0.0:%d", e.cfg.ListenPort)

	slog.Info("ZRO Edge Data Plane PoP started",
		"pop_code", e.cfg.PoPCode,
		"region", e.cfg.Region,
		"public_endpoint", e.cfg.PublicEndpoint,
		"pubkey", e.keyPair.PublicKey,
		"listen_port", e.cfg.ListenPort)

	// STUN is answered from the shared WireGuard socket by handleControlPacket;
	// no separate listener is needed.

	// Launch DERP Encrypted Packet Relay server over TCP
	derpSrv, err := derp.NewServer(e.keyPair)
	if err == nil {
		e.derpServer = derpSrv
		tcpListener, err := net.Listen("tcp", listenAddr)
		if err == nil {
			e.derpListener = tcpListener
			slog.Info("ZRO Edge DERP packet relay listening", "addr", listenAddr)
			e.wg.Add(1)
			go func() {
				defer e.wg.Done()
				_ = e.derpServer.Serve(tcpListener)
			}()
		}
	}

	// Connect gRPC client if plane transport is set to grpc
	if strings.EqualFold(e.cfg.PlaneTransport, "grpc") {
		grpcTarget := e.cfg.PlaneEndpoint
		grpcTarget = strings.TrimPrefix(grpcTarget, "http://")
		grpcTarget = strings.TrimPrefix(grpcTarget, "https://")
		gc, err := controlgrpc.NewClient(grpcTarget)
		if err == nil {
			e.grpcClient = gc
			slog.Info("Edge PoP connected to Control Plane via gRPC", "target", grpcTarget)
		} else {
			slog.Warn("Failed to initialize gRPC client for Edge PoP", "error", err)
		}
	}

	// Launch Control Plane config synchronization and registration loop
	e.wg.Add(1)
	go e.syncWorker(ctx)

	// Launch real-time event listener for instant mesh updates
	e.wg.Add(1)
	go e.realtimeListener(ctx)

	return nil
}

// Stop shuts down the Edge PoP daemon.
func (e *PoPDaemon) Stop() error {
	if e.cancel != nil {
		e.cancel()
	}
	if e.wgManager != nil {
		_ = e.wgManager.Close()
	}
	if e.udpListener != nil {
		_ = e.udpListener.Close()
	}
	if e.tunDev != nil {
		_ = e.tunDev.Close()
	}
	if e.derpListener != nil {
		_ = e.derpListener.Close()
	}
	if e.derpServer != nil {
		_ = e.derpServer.Close()
	}
	if e.grpcClient != nil {
		_ = e.grpcClient.Close()
	}
	e.wg.Wait()
	return nil
}

func (e *PoPDaemon) registerWithControlPlane(ctx context.Context) bool {
	regPayload := map[string]any{
		"pop_code":        e.cfg.PoPCode,
		"region":          e.cfg.Region,
		"public_endpoint": e.cfg.PublicEndpoint,
		"public_key":      e.keyPair.PublicKey,
		"weight":          100,
		"is_anycast":      e.cfg.IsAnycast,
	}

	body, err := json.Marshal(regPayload)
	if err != nil {
		return false
	}

	req, err := http.NewRequestWithContext(ctx, "POST", e.cfg.PlaneEndpoint+"/api/v1/edge/register", bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	if e.cfg.EdgeAPIKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.cfg.EdgeAPIKey)
		req.Header.Set("X-Edge-Key", e.cfg.EdgeAPIKey)
	}

	resp, err := e.httpClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		slog.Info("Registered Edge PoP with Control Plane", "pop_code", e.cfg.PoPCode, "plane", e.cfg.PlaneEndpoint)
		return true
	}
	slog.Warn("Failed registration with Control Plane (will retry in background)", "pop_code", e.cfg.PoPCode, "error", err)
	return false
}

func (e *PoPDaemon) sendHeartbeat(ctx context.Context) {
	e.peersMu.RLock()
	peersCount := e.peerCount
	e.peersMu.RUnlock()

	hbPayload := map[string]any{
		"pop_code":        e.cfg.PoPCode,
		"status":          "online",
		"peers_count":     peersCount,
		"public_endpoint": e.cfg.PublicEndpoint,
		"timestamp":       time.Now(),
	}

	body, err := json.Marshal(hbPayload)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", e.cfg.PlaneEndpoint+"/api/v1/edge/heartbeat", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if e.cfg.EdgeAPIKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.cfg.EdgeAPIKey)
		req.Header.Set("X-Edge-Key", e.cfg.EdgeAPIKey)
	}

	resp, err := e.httpClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

func (e *PoPDaemon) syncWorker(ctx context.Context) {
	defer e.wg.Done()

	registered := e.registerWithControlPlane(ctx)
	if registered {
		e.sendHeartbeat(ctx)
		e.syncMeshTopology(ctx)
	}

	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !registered {
				registered = e.registerWithControlPlane(ctx)
			}
			if registered {
				e.sendHeartbeat(ctx)
				e.syncMeshTopology(ctx)
			}
		}
	}
}

func (e *PoPDaemon) syncMeshTopology(ctx context.Context) {
	if e.grpcClient != nil {
		gResp, err := e.grpcClient.SyncEdgeMesh(ctx, &v1.EdgeSyncRequest{
			PopCode: e.cfg.PoPCode,
		})
		if err == nil && gResp != nil {
			e.peersMu.Lock()
			e.peerCount = len(gResp.Nodes)
			e.peersMu.Unlock()

			for _, p := range gResp.Pops {
				if p.PopCode != e.cfg.PoPCode && p.PublicKey != "" {
					_ = e.wgManager.ApplyPeer(wireguard.PeerConfig{
						PublicKey:           p.PublicKey,
						Endpoint:            p.PublicEndpoint,
						AllowedIPs:          []string{"100.64.0.0/10", "fd00:cafe::/64"},
						PersistentKeepalive: 20 * time.Second,
					})
				}
			}

			for _, n := range gResp.Nodes {
				if n.PublicKey != "" && n.OverlayIpv4 != "" {
					var ep string
					if len(n.Endpoints) > 0 {
						ep = n.Endpoints[0]
					}
					_ = e.wgManager.ApplyPeer(wireguard.PeerConfig{
						PublicKey:           n.PublicKey,
						Endpoint:            ep,
						AllowedIPs:          []string{n.OverlayIpv4 + "/32"},
						PersistentKeepalive: 25 * time.Second,
					})
					e.routingTable.SetRoute(n.OverlayIpv4, router.RouteTarget{
						PublicKey: n.PublicKey,
						Endpoint:  ep,
					})
					if err := netcfg.AddHostRoute(e.cfg.InterfaceName, n.OverlayIpv4); err != nil {
						slog.Debug("Could not add edge route for node", "node", n.OverlayIpv4, "error", err)
					}
				}
			}
			return
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", e.cfg.PlaneEndpoint+"/api/v1/edge/sync", nil)
	if err != nil {
		return
	}
	if e.cfg.EdgeAPIKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.cfg.EdgeAPIKey)
		req.Header.Set("X-Edge-Key", e.cfg.EdgeAPIKey)
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var syncData struct {
		PoPs  []core.EdgePoP `json:"pops"`
		Nodes []core.Node    `json:"nodes"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&syncData); err != nil {
		return
	}

	e.peersMu.Lock()
	e.peerCount = len(syncData.Nodes)
	e.peersMu.Unlock()

	// 1. Establish backbone mesh with other PoPs
	for _, p := range syncData.PoPs {
		if p.PoPCode != e.cfg.PoPCode && p.PublicKey != "" {
			_ = e.wgManager.ApplyPeer(wireguard.PeerConfig{
				PublicKey:           p.PublicKey,
				Endpoint:            p.PublicEndpoint,
				AllowedIPs:          []string{"100.64.0.0/10", "fd00:cafe::/64"},
				PersistentKeepalive: 20 * time.Second,
			})
		}
	}

	// 2. Configure routing for active nodes
	for _, n := range syncData.Nodes {
		if n.PublicKey != "" && n.OverlayIPv4 != "" {
			var ep string
			if len(n.Endpoints) > 0 {
				ep = n.Endpoints[0]
			}
			_ = e.wgManager.ApplyPeer(wireguard.PeerConfig{
				PublicKey:           n.PublicKey,
				Endpoint:            ep,
				AllowedIPs:          []string{n.OverlayIPv4 + "/32"},
				PersistentKeepalive: 25 * time.Second,
			})
			e.routingTable.SetRoute(n.OverlayIPv4, router.RouteTarget{
				PublicKey: n.PublicKey,
				Endpoint:  ep,
			})
			if err := netcfg.AddHostRoute(e.cfg.InterfaceName, n.OverlayIPv4); err != nil {
				slog.Debug("Could not add edge route for node", "node", n.OverlayIPv4, "error", err)
			}
		}
	}
}

// PublicKey returns the Edge PoP WireGuard public key.
func (e *PoPDaemon) PublicKey() string {
	return e.keyPair.PublicKey
}

func (e *PoPDaemon) realtimeListener(ctx context.Context) {
	defer e.wg.Done()

	if e.grpcClient != nil {
		_ = e.grpcClient.StreamEvents(ctx, "edge", e.cfg.PoPCode, func(evt *v1.MeshEvent) {
			if evt != nil {
				slog.Info("Real-time topology update event received at Edge PoP via gRPC", "pop_code", e.cfg.PoPCode, "event", evt.EventType)
				e.syncMeshTopology(ctx)
			}
		})
		return
	}

	wsURL := e.cfg.PlaneEndpoint + "/api/v1/ws"
	if strings.HasPrefix(wsURL, "https://") {
		wsURL = "wss://" + strings.TrimPrefix(wsURL, "https://")
	} else if strings.HasPrefix(wsURL, "http://") {
		wsURL = "ws://" + strings.TrimPrefix(wsURL, "http://")
	}

	origin := e.cfg.PlaneEndpoint

	for {
		select {
		case <-ctx.Done():
			return
		default:
			wsCfg, err := websocket.NewConfig(wsURL, origin)
			if err != nil {
				return
			}
			if e.cfg.EdgeAPIKey != "" {
				wsCfg.Header.Set("X-Edge-Key", e.cfg.EdgeAPIKey)
			}
			conn, err := websocket.DialConfig(wsCfg)
			if err != nil {
				select {
				case <-ctx.Done():
					return
				case <-time.After(2 * time.Second):
					continue
				}
			}

			slog.Info("Edge PoP connected to Control Plane real-time WebSocket stream", "pop_code", e.cfg.PoPCode, "url", wsURL)

			for {
				var raw string
				err := websocket.Message.Receive(conn, &raw)
				if err != nil {
					_ = conn.Close()
					break
				}

				var evt struct {
					Event string `json:"event"`
				}
				if err := json.Unmarshal([]byte(raw), &evt); err == nil {
					if evt.Event == "node_enrolled" || evt.Event == "pop_registered" || evt.Event == "edge_sync" || evt.Event == "delta" {
						slog.Info("Real-time topology update event received at Edge PoP", "pop_code", e.cfg.PoPCode, "event", evt.Event)
						e.syncMeshTopology(ctx)
					}
				}
			}
		}
	}
}
