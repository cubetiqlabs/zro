package edge

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/cubis/zro/pkg/config"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/crypto"
	"github.com/cubis/zro/pkg/dataplane/derp"
	"github.com/cubis/zro/pkg/dataplane/router"
	"github.com/cubis/zro/pkg/dataplane/wireguard"
	"github.com/cubis/zro/pkg/p2p/stun"
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

	// Launch Control Plane config synchronization loop
	e.wg.Add(1)
	go e.syncWorker(ctx)

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

func (e *PoPDaemon) syncWorker(ctx context.Context) {
	defer e.wg.Done()

	// Sync Edge PoP backbone topology with other PoPs
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.syncOtherPoPs(ctx)
		}
	}
}

func (e *PoPDaemon) syncOtherPoPs(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, "GET", e.cfg.PlaneEndpoint+"/api/v1/pops", nil)
	if err != nil {
		return
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var pops []core.EdgePoP
	if err := json.NewDecoder(resp.Body).Decode(&pops); err != nil {
		return
	}

	// Establish backbone mesh with other PoPs
	for _, p := range pops {
		if p.PoPCode != e.cfg.PoPCode && p.PublicKey != "" {
			_ = e.wgManager.ApplyPeer(wireguard.PeerConfig{
				PublicKey:           p.PublicKey,
				Endpoint:            p.PublicEndpoint,
				AllowedIPs:          []string{"100.64.0.0/10", "fd00:cafe::/64"},
				PersistentKeepalive: 20 * time.Second,
			})
		}
	}
}

// PublicKey returns the Edge PoP WireGuard public key.
func (e *PoPDaemon) PublicKey() string {
	return e.keyPair.PublicKey
}
