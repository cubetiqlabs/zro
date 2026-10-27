package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cubetiqlabs/zro/pkg/config"
	controlauth "github.com/cubetiqlabs/zro/pkg/control/auth"
	controlgrpc "github.com/cubetiqlabs/zro/pkg/control/grpc"
	"github.com/cubetiqlabs/zro/pkg/crypto"
	"github.com/cubetiqlabs/zro/pkg/dataplane/derp"
	"github.com/cubetiqlabs/zro/pkg/dataplane/netcfg"
	"github.com/cubetiqlabs/zro/pkg/dataplane/tun"
	"github.com/cubetiqlabs/zro/pkg/dataplane/wireguard"
	"github.com/cubetiqlabs/zro/pkg/identity"
	"github.com/cubetiqlabs/zro/pkg/netutil"
	"github.com/cubetiqlabs/zro/pkg/p2p/stun"
	"github.com/cubetiqlabs/zro/pkg/realtime"
)

// PoPDaemon is the edge data plane daemon running at public PoPs.
type PoPDaemon struct {
	cfg          *config.EdgeConfig
	keyPair      *crypto.KeyPair
	wgManager    *wireguard.Manager
	tunDev       tun.Device
	routed       map[string]bool // overlay prefixes already routed into the TUN (sync goroutine only)
	udpListener  *net.UDPConn
	derpServer   *derp.Server
	derpListener net.Listener
	httpClient   *http.Client
	registered   chan struct{} // closed after the first successful registration
	regOnce      sync.Once
	popKey       controlauth.TokenHolder // per-PoP credential issued at first registration
	grpcClient   *controlgrpc.Client
	peerCount    int
	knownKeys    atomic.Pointer[map[[32]byte]struct{}] // public keys allowed on the DERP relay
	peersMu      sync.RWMutex
	syncMu       sync.Mutex   // one mesh sync at a time: the worker and realtime events both trigger it
	synced       bool         // first mesh sync done (guarded by peersMu)
	lastSyncWarn atomic.Int64 // unix nanos of the last sync failure warning

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// popKeyFile is the state-dir file holding the PoP's own credential.
const popKeyFile = "edge.popkey"

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
		kp, err = identity.LoadOrCreateKey(cfg.StateDir, "edge.key")
		if err != nil {
			return nil, fmt.Errorf("failed to load WireGuard identity: %w", err)
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
		cfg:         cfg,
		keyPair:     kp,
		tunDev:      tunDev,
		udpListener: udpConn,
		routed:      make(map[string]bool),
		registered:  make(chan struct{}),
	}
	if cfg.StateDir != "" {
		if key, err := identity.ReadSecret(cfg.StateDir, popKeyFile); err == nil {
			e.popKey.Set(key)
		}
	}
	e.httpClient = &http.Client{
		Timeout:   10 * time.Second,
		Transport: controlauth.NewBearerTransport(newPlaneTransport(), cfg.PlaneEndpoint, e.credential),
	}

	// Without a kernel TUN (no privileges) nothing would route between peers, so
	// forward in userspace instead of silently dropping relayed traffic.
	if md, ok := tunDev.(*tun.MemoryDevice); ok {
		slog.Warn("No kernel TUN available: forwarding between peers in userspace (lower throughput)", "interface", iface)
		go md.Hairpin()
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
	if err := netcfg.EnsureForwardAccept(iface); err != nil {
		slog.Warn("Could not allow overlay forwarding in the host firewall (relay may fail)", "error", err)
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
		// Only keys the mesh knows (nodes and PoPs) may use the relay.
		derpSrv.Authorize = e.isKnownKey
		derpSrv.Limits = derp.Limits{
			MaxConns: e.cfg.DERPMaxConns, MaxConnsPerIP: e.cfg.DERPMaxConnsPerIP,
			PacketsPerSec: e.cfg.DERPPacketsPerSec, BytesPerSec: e.cfg.DERPBytesPerSec,
		}
		// The PoP's own WireGuard device is reachable through the relay too, so
		// nodes behind UDP-hostile networks can still handshake with it.
		if err := e.wgManager.AttachRelay(derpSrv.Local()); err != nil {
			slog.Warn("DERP relay could not be attached to the edge WireGuard device", "error", err)
		}
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
		if e.cfg.GRPCEndpoint != "" {
			grpcTarget = e.cfg.GRPCEndpoint
		}
		gc, err := controlgrpc.DialPlane(e.cfg.PlaneEndpoint, e.cfg.PlaneGRPC, e.credential)
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
	e.announceShutdown()
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

	resp, err := e.httpClient.Do(req)
	if err != nil {
		slog.Warn("Failed registration with Control Plane (will retry in background)", "pop_code", e.cfg.PoPCode, "error", err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		slog.Warn("Control Plane rejected Edge PoP registration (will retry in background)", "pop_code", e.cfg.PoPCode, "status", resp.StatusCode)
		return false
	}

	// The first registration claims the PoP and returns its own credential, which
	// replaces the shared registration key from then on.
	var reg struct {
		PopKey      string `json:"pop_key"`
		OverlayIPv4 string `json:"overlay_ipv4"`
		OverlayIPv6 string `json:"overlay_ipv6"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	if reg.OverlayIPv4 != "" {
		if err := netcfg.ConfigureOverlay(e.cfg.InterfaceName, reg.OverlayIPv4, reg.OverlayIPv6, e.cfg.MTU); err != nil {
			slog.Warn("Could not assign the PoP mesh address", "address", reg.OverlayIPv4, "error", err)
		} else {
			slog.Info("PoP mesh address assigned", "ipv4", reg.OverlayIPv4, "ipv6", reg.OverlayIPv6)
		}
	}
	if reg.PopKey != "" {
		e.popKey.Set(reg.PopKey)
		if e.cfg.StateDir != "" {
			if err := identity.WriteSecret(e.cfg.StateDir, popKeyFile, reg.PopKey); err != nil {
				slog.Error("Could not persist the PoP credential; the PoP will need an admin reset after a restart", "error", err)
			}
		} else {
			slog.Warn("No state_dir configured: the PoP credential is kept in memory only and a restart needs an admin reset")
		}
	}
	slog.Info("Registered Edge PoP with Control Plane", "pop_code", e.cfg.PoPCode, "plane", e.cfg.PlaneEndpoint)
	e.regOnce.Do(func() { close(e.registered) })
	return true
}

// announceShutdown tells the plane this PoP is going away so it is marked
// offline immediately instead of after the heartbeat timeout (best effort).
func (e *PoPDaemon) announceShutdown() {
	if e.popKey.Get() == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.PlaneEndpoint+"/api/v1/edge/deregister", nil)
	if err != nil {
		return
	}
	if resp, err := e.httpClient.Do(req); err == nil {
		_ = resp.Body.Close()
	}
}

// credential is the secret sent to the plane: the PoP's own credential once it
// has one, otherwise the shared registration key.
func (e *PoPDaemon) credential() string {
	if k := e.popKey.Get(); k != "" {
		return k
	}
	return e.cfg.EdgeAPIKey
}

// sendHeartbeat reports whether the plane accepted the heartbeat. A rejection
// (PoP unknown after a plane reset, credential refused) means the PoP must
// register again.
func (e *PoPDaemon) sendHeartbeat(ctx context.Context) bool {
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
		return true
	}

	req, err := http.NewRequestWithContext(ctx, "POST", e.cfg.PlaneEndpoint+"/api/v1/edge/heartbeat", bytes.NewReader(body))
	if err != nil {
		return true
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		slog.Warn("Heartbeat to Control Plane failed", "pop_code", e.cfg.PoPCode, "error", err)
		return true // plane unreachable: keep credentials, retry next tick
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusAccepted {
		return true
	}
	if resp.StatusCode >= 500 {
		return true
	}
	slog.Warn("Control Plane rejected heartbeat; registering again", "pop_code", e.cfg.PoPCode, "status", resp.StatusCode)
	return false
}

func (e *PoPDaemon) syncWorker(ctx context.Context) {
	defer e.wg.Done()

	registered := e.registerWithControlPlane(ctx)
	if registered {
		registered = e.sendHeartbeat(ctx)
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
				registered = e.sendHeartbeat(ctx)
				e.syncMeshTopology(ctx)
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
	// The event stream needs the PoP's own credential, which registration issues.
	select {
	case <-e.registered:
	case <-ctx.Done():
		return
	}
	realtime.Run(ctx, realtime.Config{
		Endpoint:   e.cfg.PlaneEndpoint,
		GRPC:       e.grpcClient,
		Role:       "edge",
		ID:         e.cfg.PoPCode,
		Credential: e.credential,
		Events:     []string{"node_joined", "node_left", "mesh_graph_updated", "pop_status_changed", "edge_registered"},
		Debounce:   30 * time.Millisecond,
	}, func(ctx context.Context, evs []string) {
		slog.Debug("Mesh change received", "pop_code", e.cfg.PoPCode, "events", evs)
		e.syncMeshTopology(ctx)
	})
}

// planeTransport talks to the plane, often through a CDN or load balancer that
// closes idle connections without notice. Idle connections are dropped early,
// and a request that hits a connection the peer already reset is replayed once
// on a fresh one (every edge call to the plane is safe to repeat).
type planeTransport struct{ base *http.Transport }

func newPlaneTransport() http.RoundTripper {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.IdleConnTimeout = 30 * time.Second
	return &planeTransport{base: t}
}

func (p *planeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := p.base.RoundTrip(req)
	if err == nil || !isConnReset(err) || req.Context().Err() != nil {
		return resp, err
	}
	if req.Body != nil && req.GetBody != nil {
		body, gerr := req.GetBody()
		if gerr != nil {
			return nil, err
		}
		req = req.Clone(req.Context())
		req.Body = body
	} else if req.Body != nil {
		return nil, err
	}
	p.base.CloseIdleConnections()
	return p.base.RoundTrip(req)
}

func isConnReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
