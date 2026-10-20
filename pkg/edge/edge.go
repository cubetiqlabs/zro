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

	"github.com/cubis/zro/pkg/config"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/crypto"
	"github.com/cubis/zro/pkg/dataplane/derp"
	"github.com/cubis/zro/pkg/dataplane/router"
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
	routingTable *router.Table
	udpListener  *net.UDPConn
	derpServer   *derp.Server
	derpListener net.Listener
	httpClient   *http.Client

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

	wgMgr, err := wireguard.NewManager("zro-edge")
	if err != nil {
		return nil, fmt.Errorf("failed to init wireguard manager: %w", err)
	}

	// Resolve public or private endpoint dynamically (auto discovery, env override, or internal mode)
	resolvedEndpoint := netutil.ResolveEndpoint(cfg.PublicEndpoint, cfg.ListenPort, cfg.UsePrivateIP)
	slog.Info("Edge endpoint configuration resolved",
		"configured", cfg.PublicEndpoint,
		"resolved", resolvedEndpoint,
		"use_private_ip", cfg.UsePrivateIP)
	cfg.PublicEndpoint = resolvedEndpoint

	return &PoPDaemon{
		cfg:          cfg,
		keyPair:      kp,
		wgManager:    wgMgr,
		routingTable: router.NewTable(),
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// Start launches the Edge PoP listener, STUN responder, and config sync worker.
func (e *PoPDaemon) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel

	listenAddr := fmt.Sprintf("0.0.0.0:%d", e.cfg.ListenPort)
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP %s: %w", listenAddr, err)
	}
	e.udpListener = conn

	slog.Info("ZRO Edge Data Plane PoP started",
		"pop_code", e.cfg.PoPCode,
		"region", e.cfg.Region,
		"public_endpoint", e.cfg.PublicEndpoint,
		"pubkey", e.keyPair.PublicKey,
		"listen_port", e.cfg.ListenPort)

	// Launch STUN packet responder loop
	e.wg.Add(1)
	go e.stunServerLoop(ctx)

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
	if e.udpListener != nil {
		_ = e.udpListener.Close()
	}
	if e.derpListener != nil {
		_ = e.derpListener.Close()
	}
	if e.derpServer != nil {
		_ = e.derpServer.Close()
	}
	if e.wgManager != nil {
		_ = e.wgManager.Close()
	}
	e.wg.Wait()
	return nil
}

func (e *PoPDaemon) stunServerLoop(ctx context.Context) {
	defer e.wg.Done()
	buf := make([]byte, 2048)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			_ = e.udpListener.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, clientAddr, err := e.udpListener.ReadFromUDP(buf)
			if err != nil {
				continue
			}

			// Respond to STUN queries from clients behind NAT
			_ = stun.ServeSTUN(e.udpListener, buf[:n], clientAddr)
		}
	}
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
	if err == nil {
		_ = resp.Body.Close()
		slog.Info("Registered Edge PoP with Control Plane", "pop_code", e.cfg.PoPCode, "plane", e.cfg.PlaneEndpoint)
		return true
	}
	slog.Warn("Failed registration with Control Plane (will retry in background)", "pop_code", e.cfg.PoPCode, "error", err)
	return false
}

func (e *PoPDaemon) syncWorker(ctx context.Context) {
	defer e.wg.Done()

	registered := e.registerWithControlPlane(ctx)
	if registered {
		e.syncMeshTopology(ctx)
	}

	ticker := time.NewTicker(5 * time.Second)
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
				e.syncMeshTopology(ctx)
			}
		}
	}
}

func (e *PoPDaemon) syncMeshTopology(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, "GET", e.cfg.PlaneEndpoint+"/api/v1/edge/sync", nil)
	if err != nil {
		return
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
		}
	}
}

// PublicKey returns the Edge PoP WireGuard public key.
func (e *PoPDaemon) PublicKey() string {
	return e.keyPair.PublicKey
}

func (e *PoPDaemon) realtimeListener(ctx context.Context) {
	defer e.wg.Done()

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
			conn, err := websocket.Dial(wsURL, "", origin)
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
