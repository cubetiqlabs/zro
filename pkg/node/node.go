package node

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
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
	networkID    uuid.UUID
	overlayIPv4  string
	overlayIPv6  string
	primaryPoP   core.EdgePoP
	secondaryPoP *core.EdgePoP
	peers        map[string]core.Node // pubKey -> node

	tunDev       tun.Device
	wgManager    *wireguard.Manager
	routingTable *router.Table
	udpConn      *net.UDPConn
	discoEngine  *disco.Engine
	derpClient   *derp.Client
	tunnelClient *tunnel.Client
	httpClient   *http.Client

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
		cfg:          cfg,
		keyPair:      kp,
		peers:        make(map[string]core.Node),
		tunDev:       tunDev,
		wgManager:    wgMgr,
		routingTable: router.NewTable(),
		tunnelClient: tunnel.NewClient(),
		httpClient:   &http.Client{Timeout: 10 * time.Second},
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

	// 2. Discover reflexive STUN endpoint if plane is reachable
	var endpoints []string
	discovered, err := stun.DiscoverPublicEndpoint(udpConn, "127.0.0.1:51820", 1*time.Second)
	if err == nil && discovered != nil {
		endpoints = append(endpoints, discovered.String())
	}

	// 3. Enroll with Control Plane
	enrollReq := server.EnrollRequest{
		Token:     d.cfg.EnrollmentToken,
		PublicKey: d.keyPair.PublicKey,
		Hostname:  d.cfg.Hostname,
		NodeType:  core.NodeTypePeer,
		Tags:      core.StringList(d.cfg.Tags),
		Endpoints: core.StringList(endpoints),
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
	d.primaryPoP = enrollResp.PrimaryPoP
	d.secondaryPoP = enrollResp.SecondaryPoP

	slog.Info("Enrolled into overlay mesh",
		"overlay_ipv4", d.overlayIPv4,
		"overlay_ipv6", d.overlayIPv6,
		"delegated_pop", d.primaryPoP.PoPCode,
		"pop_endpoint", d.primaryPoP.PublicEndpoint)

	// 4. Connect to Delegated Primary Edge PoP
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

func (d *Daemon) connectPeer(ctx context.Context, peer core.Node) {
	d.peers[peer.PublicKey] = peer

	// Try P2P hole punch if peer has reflexive endpoints
	var directEndpoint string
	if d.cfg.EnableP2P && len(peer.Endpoints) > 0 {
		for _, ep := range peer.Endpoints {
			punchRes, err := puncher.Punch(ctx, d.udpConn, ep, 500*time.Millisecond)
			if err == nil && punchRes.Success {
				directEndpoint = ep
				slog.Info("Direct P2P tunnel established with peer", "peer", peer.Hostname, "endpoint", ep)
				break
			}
		}
	}

	// Configure peer on WireGuard
	isDirect := directEndpoint != ""
	ep := directEndpoint
	if !isDirect && peer.AssignedPoP != nil {
		ep = peer.AssignedPoP.PublicEndpoint
	}

	_ = d.wgManager.ApplyPeer(wireguard.PeerConfig{
		PublicKey:           peer.PublicKey,
		Endpoint:            ep,
		AllowedIPs:          []string{peer.OverlayIPv4 + "/32"},
		PersistentKeepalive: 25 * time.Second,
	})

	d.routingTable.SetRoute(peer.OverlayIPv4, router.RouteTarget{
		PublicKey:   peer.PublicKey,
		Endpoint:    ep,
		IsDirectP2P: isDirect,
	})
}

func (d *Daemon) probeWorker(ctx context.Context) {
	defer d.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Send latency probe to delegated primary PoP
			sample := core.LatencySample{
				NodeID:     d.nodeID,
				PoPCode:    d.primaryPoP.PoPCode,
				RTT:        12 * time.Millisecond, // simulated probe measure
				PacketLoss: 0.0,
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

// PublicKey returns the node's WireGuard public key.
func (d *Daemon) PublicKey() string {
	return d.keyPair.PublicKey
}
