package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	v1 "github.com/cubetiqlabs/zro/api/proto/v1"
	"github.com/cubetiqlabs/zro/pkg/agent"
	"github.com/cubetiqlabs/zro/pkg/config"
	controlauth "github.com/cubetiqlabs/zro/pkg/control/auth"
	controlgrpc "github.com/cubetiqlabs/zro/pkg/control/grpc"
	"github.com/cubetiqlabs/zro/pkg/control/server"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/cubetiqlabs/zro/pkg/crypto"
	"github.com/cubetiqlabs/zro/pkg/dataplane/tun"
	"github.com/cubetiqlabs/zro/pkg/dataplane/wireguard"
	"github.com/cubetiqlabs/zro/pkg/gateway/acme"
	"github.com/cubetiqlabs/zro/pkg/gateway/balancer"
	"github.com/cubetiqlabs/zro/pkg/gateway/proxy"
	"github.com/cubetiqlabs/zro/pkg/identity"
	"github.com/cubetiqlabs/zro/pkg/p2p/stun"
	"github.com/cubetiqlabs/zro/pkg/realtime"
	"github.com/google/uuid"
)

// Daemon represents the running ingress gateway and cloud-native load balancer.
type Daemon struct {
	cfg          *config.GatewayConfig
	keyPair      *crypto.KeyPair
	nodeID       uuid.UUID
	networkID    string
	overlayIPv4  string
	overlayIPv6  string
	primaryPoP   core.EdgePoP
	secondaryPoP *core.EdgePoP
	popMu        sync.RWMutex

	tunDev          tun.Device
	dev             *agent.Device
	wgManager       *wireguard.Manager
	udpConn         *net.UDPConn
	proxyEngine     *proxy.Engine
	healthChecker   *proxy.HealthChecker
	httpClient      *http.Client
	token           controlauth.TokenHolder // bearer token issued at enrollment
	popLink         *agent.PoPLink
	dynMu           sync.Mutex      // guards dynamicHosts
	dynamicHosts    map[string]bool // hostnames installed from the plane (static config routes are never pruned)
	overlayPrefixes []string        // routed into the interface; reported by the plane at enrollment
	grpcClient      *controlgrpc.Client
	httpServer      *http.Server
	httpsServer     *http.Server

	stunMu      sync.Mutex
	stunWaiters map[[12]byte]chan *stun.ReflexiveAddress

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewDaemon initializes a new ingress gateway daemon.
func NewDaemon(cfg *config.GatewayConfig) (*Daemon, error) {
	kp, err := identity.LoadOrCreateKey(cfg.StateDir, "gateway.key")
	if err != nil {
		return nil, fmt.Errorf("failed to load WireGuard identity: %w", err)
	}

	if cfg.InterfaceName == "" {
		cfg.InterfaceName = "zro-gw"
	}
	if cfg.MTU <= 0 {
		cfg.MTU = 1420
	}
	if cfg.Strategy == "" {
		cfg.Strategy = "latency"
	}
	if cfg.HealthCheckIntervalMs <= 0 {
		cfg.HealthCheckIntervalMs = 3000
	}
	if cfg.SyncIntervalMs <= 0 {
		cfg.SyncIntervalMs = 3000
	}
	if cfg.HealthCheckPath == "" {
		cfg.HealthCheckPath = "/health"
	}

	dev, err := agent.OpenDevice(cfg.InterfaceMode, cfg.InterfaceName, cfg.MTU)
	if err != nil {
		return nil, err
	}
	tunDev := dev.TUN

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: cfg.ListenPort})
	if err != nil {
		_ = tunDev.Close()
		return nil, fmt.Errorf("failed to bind shared UDP socket: %w", err)
	}

	d := &Daemon{
		cfg:           cfg,
		keyPair:       kp,
		tunDev:        tunDev,
		dev:           dev,
		udpConn:       udpConn,
		proxyEngine:   proxy.NewEngine(),
		healthChecker: proxy.NewHealthChecker(2 * time.Second),
		stunWaiters:   make(map[[12]byte]chan *stun.ReflexiveAddress),
		dynamicHosts:  make(map[string]bool),
	}

	agent.LoadToken(cfg.StateDir, "gateway.token", &d.token)
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
	d.overlayPrefixes = core.OverlayPrefixes("", "") // refined from the enrollment response
	d.popLink = &agent.PoPLink{WG: wgMgr, Interface: cfg.InterfaceName, OSRoutes: !dev.Userspace()}
	if dev.Userspace() {
		// Backends live on the overlay, which only the userspace stack can reach.
		d.proxyEngine.Transport.DialContext = dev.Net.DialContext
		d.healthChecker.SetDialer(dev.Net.DialContext)
	}
	d.loadStaticRoutes()
	return d, nil
}

// discoverReflexive runs a STUN exchange on the shared socket so the endpoint
// advertised to the control plane matches WireGuard's actual NAT mapping.
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

// handleControlPacket is called by the shared WireGuard bind for non-WireGuard
// datagrams.
func (d *Daemon) handleControlPacket(packet []byte, remoteAddr *net.UDPAddr) {
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

	if stun.IsBindingRequest(packet) {
		_ = stun.ServeSTUN(d.udpConn, packet, remoteAddr)
	}
}

// Start boots the gateway daemon, enrolls with the control plane, connects to the overlay mesh,
// loads static and dynamic routes, and starts reverse proxy listeners.
func (d *Daemon) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	d.cancel = cancel

	// Connect gRPC client if plane transport is set to grpc
	if strings.EqualFold(d.cfg.PlaneTransport, "grpc") {
		grpcTarget := d.cfg.PlaneEndpoint
		if d.cfg.GRPCEndpoint != "" {
			grpcTarget = d.cfg.GRPCEndpoint
		}
		gc, err := controlgrpc.DialPlane(d.cfg.PlaneEndpoint, d.cfg.PlaneGRPC, d.token.Get)
		if err == nil {
			d.grpcClient = gc
			slog.Info("ZRO Ingress Gateway connected to Control Plane via gRPC", "target", grpcTarget)
		} else {
			slog.Warn("Failed to initialize gRPC client for Gateway", "error", err)
		}
	}

	// 1. Load static routes from config
	d.loadStaticRoutes()

	// 2. Overlay mesh enrollment & Edge PoP peering (if plane endpoint & token are provided)
	if d.cfg.PlaneEndpoint != "" && d.cfg.EnrollmentToken != "" {
		if err := d.enrollAndConnect(ctx); err != nil {
			slog.Warn("Gateway overlay enrollment failed (will retry in background)", "error", err)
		} else {
			// Fetch initial dynamic routes
			_ = d.SyncRoutesOnce(ctx)
		}

		// Launch background dynamic route synchronization worker
		d.wg.Add(1)
		go d.syncWorker(ctx)

		// Launch real-time event listener for instant sub-millisecond route updates
		d.wg.Add(1)
		go d.realtimeListener(ctx)
	}

	// 3. Launch active health checking worker across all registered route backends
	d.wg.Add(1)
	go d.healthCheckWorker(ctx)

	// 4. Automated ACME TLS termination if enabled
	var httpHandler http.Handler = d.proxyEngine
	if d.cfg.AutoTLS && d.cfg.Domain != "" {
		acmeMgr, err := acme.NewManager(acme.Config{
			Enabled: true,
			Domains: []string{d.cfg.Domain},
			CertDir: d.cfg.CertDir,
		})
		if err == nil {
			d.httpsServer = &http.Server{
				Addr:         d.cfg.ListenHTTPS,
				Handler:      d.proxyEngine,
				TLSConfig:    acmeMgr.TLSConfig(),
				ReadTimeout:  15 * time.Second,
				WriteTimeout: 15 * time.Second,
			}
			// Port 80 must answer ACME HTTP-01 challenges as well, otherwise issuance
			// depends on TLS-ALPN-01 alone; everything else still reaches the proxy.
			httpHandler = acmeMgr.HTTPHandler(d.proxyEngine)
			go func() {
				slog.Info("ZRO Ingress Gateway HTTPS listening with AutoTLS", "addr", d.cfg.ListenHTTPS, "domain", d.cfg.Domain)
				if err := d.httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
					slog.Error("Gateway HTTPS server error", "error", err)
				}
			}()
		} else {
			slog.Error("AutoTLS is enabled but the ACME manager could not start; serving HTTP only", "error", err)
		}
	}

	// 5. Start HTTP reverse proxy listener
	if d.cfg.ListenHTTP != "" {
		d.httpServer = &http.Server{
			Addr:         d.cfg.ListenHTTP,
			Handler:      httpHandler,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
		}

		go func() {
			slog.Info("ZRO Ingress Gateway HTTP listening", "addr", d.cfg.ListenHTTP, "hostname", d.cfg.Hostname)
			if err := d.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("Gateway HTTP server error", "error", err)
			}
		}()
	}

	return nil
}

// Stop gracefully terminates listeners and closes mesh interfaces.
func (d *Daemon) Stop() error {
	if d.cancel != nil {
		d.cancel()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if d.httpServer != nil {
		_ = d.httpServer.Shutdown(shutdownCtx)
	}
	if d.httpsServer != nil {
		_ = d.httpsServer.Shutdown(shutdownCtx)
	}

	if d.wgManager != nil {
		_ = d.wgManager.Close()
	}
	if d.udpConn != nil {
		_ = d.udpConn.Close()
	}
	if d.tunDev != nil {
		_ = d.tunDev.Close()
	}
	if d.grpcClient != nil {
		_ = d.grpcClient.Close()
	}

	d.wg.Wait()
	return nil
}

func (d *Daemon) loadStaticRoutes() {
	// Single domain shortcut in config
	if d.cfg.Domain != "" && len(d.cfg.StaticRoutes) == 0 {
		backends := []*balancer.Backend{
			{Address: "127.0.0.1:8080", Healthy: true, Weight: 100},
		}
		bal := balancer.NewBalancer(balancer.Strategy(d.cfg.Strategy), backends)
		d.proxyEngine.RegisterRoute(d.cfg.Domain, bal)
	}

	for _, sr := range d.cfg.StaticRoutes {
		var backends []*balancer.Backend
		for _, addr := range sr.Backends {
			backends = append(backends, &balancer.Backend{
				Address: addr,
				Weight:  100,
				Healthy: true,
			})
		}
		strat := balancer.Strategy(sr.Strategy)
		if strat == "" {
			strat = balancer.Strategy(d.cfg.Strategy)
		}
		bal := balancer.NewBalancer(strat, backends)
		d.proxyEngine.RegisterRoute(sr.Hostname, bal)
		slog.Info("Loaded static gateway route", "hostname", sr.Hostname, "backends", len(backends), "strategy", strat)
	}
}

func (d *Daemon) enrollAndConnect(ctx context.Context) error {
	pops, _ := d.fetchPoPs(ctx)
	probes, bestPoP := d.probePoPs(ctx, pops)

	var endpoints []string
	if bestPoP != "" {
		if reflexive, err := d.discoverReflexive(bestPoP, 2*time.Second); err == nil && reflexive != nil {
			endpoints = append(endpoints, reflexive.String())
		} else if err != nil {
			slog.Warn("Could not discover gateway reflexive endpoint on shared socket", "stun_server", bestPoP, "error", err)
		}
	}

	enrollReq := server.EnrollRequest{
		Token:     d.cfg.EnrollmentToken,
		PublicKey: d.keyPair.PublicKey,
		Hostname:  d.cfg.Hostname,
		NodeType:  core.NodeTypeGateway,
		Tags:      core.StringList{"role:gateway", "env:production"},
		Endpoints: core.StringList(endpoints),
		Probes:    probes,
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
		return fmt.Errorf("gateway enrollment failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway enrollment rejected by control plane: status %d", resp.StatusCode)
	}

	var enrollResp server.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return fmt.Errorf("failed to decode gateway enrollment response: %w", err)
	}

	if d.cfg.NetworkID != "" && !strings.EqualFold(d.cfg.NetworkID, enrollResp.NetworkID) {
		return fmt.Errorf("enrolled into network %s but network_id is configured as %s; check the enrollment token", enrollResp.NetworkID, d.cfg.NetworkID)
	}
	d.token.Set(enrollResp.NodeToken)
	agent.SaveToken(d.cfg.StateDir, "gateway.token", enrollResp.NodeToken)
	d.overlayPrefixes = core.OverlayPrefixes(enrollResp.IPv4CIDR, enrollResp.IPv6CIDR)
	d.nodeID = enrollResp.NodeID
	d.networkID = enrollResp.NetworkID
	d.overlayIPv4 = enrollResp.OverlayIPv4
	d.overlayIPv6 = enrollResp.OverlayIPv6

	if err := d.dev.Configure(d.overlayIPv4, d.overlayIPv6); err != nil {
		slog.Warn("Failed to configure gateway overlay addresses", "interface", d.cfg.InterfaceName, "error", err)
	}

	d.popMu.Lock()
	d.primaryPoP = enrollResp.PrimaryPoP
	d.secondaryPoP = enrollResp.SecondaryPoP
	d.popMu.Unlock()

	slog.Info("Gateway enrolled into overlay mesh",
		"hostname", d.cfg.Hostname,
		"overlay_ipv4", d.overlayIPv4,
		"overlay_ipv6", d.overlayIPv6,
		"delegated_pop", d.primaryPoP.PoPCode,
		"pop_endpoint", d.primaryPoP.PublicEndpoint)

	// Connect to delegated Edge PoP WireGuard tunnel
	if err := d.connectToEdgePoP(d.primaryPoP); err != nil {
		slog.Warn("Failed to establish primary Edge PoP tunnel for gateway", "error", err)
	}

	return nil
}

func (d *Daemon) connectToEdgePoP(pop core.EdgePoP) error {
	return d.popLink.Connect(pop, d.overlayPrefixes)
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

// SyncRoutesOnce fetches dynamic routes from the Control Plane and updates the proxy engine.
func (d *Daemon) SyncRoutesOnce(ctx context.Context) error {
	if d.cfg.PlaneEndpoint == "" {
		return nil
	}
	routes, err := d.fetchRoutes(ctx)
	if err != nil {
		return err
	}
	d.applyRoutes(routes)
	return nil
}

// fetchRoutes retrieves this network's routes over gRPC when configured,
// falling back to REST.
func (d *Daemon) fetchRoutes(ctx context.Context) ([]server.GatewayRouteItem, error) {
	if d.grpcClient != nil {
		if g, err := d.grpcClient.GetGatewayRoutes(ctx, &v1.GatewayRoutesRequest{GatewayHostname: d.cfg.Hostname}); err == nil && g != nil {
			routes := make([]server.GatewayRouteItem, 0, len(g.Routes))
			for _, r := range g.Routes {
				item := server.GatewayRouteItem{Hostname: r.Hostname, Protocol: r.Protocol}
				for _, b := range r.Backends {
					item.Backends = append(item.Backends, server.GatewayBackendItem{Address: b.Address, Weight: int(b.Weight), Healthy: b.Healthy})
				}
				routes = append(routes, item)
			}
			return routes, nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", d.cfg.PlaneEndpoint+"/api/v1/gateway/routes", nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway routes endpoint returned %d", resp.StatusCode)
	}
	var routesResp server.GatewayRoutesResponse
	if err := json.NewDecoder(resp.Body).Decode(&routesResp); err != nil {
		return nil, err
	}
	return routesResp.Routes, nil
}

// applyRoutes installs the plane's routes and removes dynamic routes the plane
// no longer lists (a deleted tunnel or a departed node). Routes from the
// static config are never removed.
func (d *Daemon) applyRoutes(routes []server.GatewayRouteItem) {
	d.dynMu.Lock()
	defer d.dynMu.Unlock()

	seen := make(map[string]bool, len(routes))
	for _, r := range routes {
		seen[r.Hostname] = true
		backends := make([]*balancer.Backend, 0, len(r.Backends))
		for _, b := range r.Backends {
			backends = append(backends, &balancer.Backend{Address: b.Address, Weight: b.Weight, Healthy: b.Healthy})
		}
		if bal, exists := d.proxyEngine.GetRoute(r.Hostname); exists {
			bal.UpdateBackends(backends)
		} else {
			d.proxyEngine.RegisterRoute(r.Hostname, balancer.NewBalancer(balancer.Strategy(d.cfg.Strategy), backends))
			slog.Info("Registered dynamic gateway route", "hostname", r.Hostname, "backends", len(backends))
		}
		d.dynamicHosts[r.Hostname] = true
	}
	for host := range d.dynamicHosts {
		if !seen[host] {
			d.proxyEngine.UnregisterRoute(host)
			delete(d.dynamicHosts, host)
			slog.Info("Removed gateway route no longer published by the plane", "hostname", host)
		}
	}
}

func (d *Daemon) syncWorker(ctx context.Context) {
	defer d.wg.Done()
	ticker := time.NewTicker(time.Duration(d.cfg.SyncIntervalMs) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if d.nodeID == uuid.Nil {
				_ = d.enrollAndConnect(ctx)
			}
			_ = d.SyncRoutesOnce(ctx)
		}
	}
}

func (d *Daemon) healthCheckWorker(ctx context.Context) {
	defer d.wg.Done()
	ticker := time.NewTicker(time.Duration(d.cfg.HealthCheckIntervalMs) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			routes := d.proxyEngine.ListRoutes()
			for _, bal := range routes {
				backends := bal.GetBackends()
				for _, b := range backends {
					d.healthChecker.Check(ctx, b, d.cfg.HealthCheckPath)
				}
			}
		}
	}
}

// OverlayIPv4 returns the assigned static overlay IP for this gateway.
func (d *Daemon) OverlayIPv4() string {
	return d.overlayIPv4
}

// PublicKey returns the WireGuard public key of the gateway.
func (d *Daemon) PublicKey() string {
	return d.keyPair.PublicKey
}

func (d *Daemon) realtimeListener(ctx context.Context) {
	defer d.wg.Done()
	realtime.Run(ctx, realtime.Config{
		Endpoint:   d.cfg.PlaneEndpoint,
		GRPC:       d.grpcClient,
		Role:       "gateway",
		ID:         d.cfg.Hostname,
		Credential: d.token.Get,
		Events:     []string{"gateway_routes_updated", "node_left"},
	}, func(ctx context.Context, evs []string) {
		slog.Info("Route change received", "events", evs)
		_ = d.SyncRoutesOnce(ctx)
	})
}

// ProxyEngine returns the internal reverse proxy engine.
func (d *Daemon) ProxyEngine() *proxy.Engine {
	return d.proxyEngine
}
