package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	v1 "github.com/cubis/zro/api/proto/v1"
	"github.com/cubis/zro/pkg/config"
	"github.com/cubis/zro/pkg/control/delegation"
	controlgrpc "github.com/cubis/zro/pkg/control/grpc"
	"github.com/cubis/zro/pkg/control/ipam"
	"github.com/cubis/zro/pkg/control/ws"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/crypto"
	"github.com/cubis/zro/pkg/gateway/balancer"
	"github.com/cubis/zro/pkg/gateway/proxy"
	"github.com/cubis/zro/pkg/store"
	"github.com/google/uuid"
	"google.golang.org/grpc"
)

// Server is the HTTP/REST Control Plane API server for ZRO.
type Server struct {
	cfg          *config.ControlPlaneConfig
	db           *store.DB
	delegator    *delegation.Engine
	ipamCache    map[string]*ipam.IPAM // network ID (16-hex) -> IPAM allocator
	ipamMu       sync.RWMutex
	httpServer   *http.Server
	mux          *http.ServeMux
	gatewayProxy *proxy.Engine

	// High-performance Realtime Communication
	wsHub      *ws.Hub
	grpcServer *grpc.Server
	grpcCtrl   *controlgrpc.Server
	grpcLis    net.Listener

	// Notification subscribers for delta updates
	subscribersMu sync.RWMutex
	subscribers   map[chan []byte]bool
	cancel        context.CancelFunc
}

// NewServer creates a new instance of the Control Plane API Server.
func NewServer(cfg *config.ControlPlaneConfig, db *store.DB) *Server {
	delegator := delegation.NewEngine(db.EdgePoPs)
	mux := http.NewServeMux()

	s := &Server{
		cfg:         cfg,
		db:          db,
		delegator:   delegator,
		ipamCache:   make(map[string]*ipam.IPAM),
		mux:         mux,
		subscribers: make(map[chan []byte]bool),
		wsHub:       ws.NewHub(),
		grpcCtrl:    controlgrpc.NewServer(cfg, db),
	}

	if cfg.EnableGateway {
		s.gatewayProxy = proxy.NewEngine()
	}

	s.registerRoutes()
	return s
}

// Start begins listening on the configured address.
func (s *Server) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	// Launch background watcher for Edge PoP health / heartbeat tracking
	go s.popWatchWorker(ctx)

	// Start gRPC server in background if configured
	if s.cfg.GRPCListenAddr != "" {
		lis, err := net.Listen("tcp", s.cfg.GRPCListenAddr)
		if err == nil {
			s.grpcLis = lis
			s.grpcServer = grpc.NewServer()
			v1.RegisterControlPlaneServiceServer(s.grpcServer, s.grpcCtrl)
			go func() {
				slog.Info("ZRO Control Plane gRPC server listening", "addr", s.cfg.GRPCListenAddr)
				_ = s.grpcServer.Serve(lis)
			}()
		} else {
			slog.Warn("Failed to bind gRPC listener (skipping gRPC server)", "addr", s.cfg.GRPCListenAddr, "error", err)
		}
	}

	s.httpServer = &http.Server{
		Addr:         s.cfg.ListenAddr,
		Handler:      s.mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	slog.Info("ZRO Control Plane starting", "listen_addr", s.cfg.ListenAddr, "public_url", s.cfg.PublicURL)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
	if s.grpcLis != nil {
		_ = s.grpcLis.Close()
	}
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// Handler returns the HTTP handler (useful for testing).
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /health", s.handleHealth)

	// Network Management (ZeroTier-styled 16-hex Network ID)
	s.mux.HandleFunc("POST /api/v1/networks", s.handleCreateNetwork)
	s.mux.HandleFunc("GET /api/v1/networks", s.handleListNetworks)

	// Edge PoPs, Dynamic Registration & Real-time Heartbeats
	s.mux.HandleFunc("GET /api/v1/pops", s.handleListPoPs)
	s.mux.HandleFunc("POST /api/v1/edge/register", s.handleRegisterEdgePoP)
	s.mux.HandleFunc("POST /api/v1/edge/heartbeat", s.handleEdgeHeartbeat)
	s.mux.HandleFunc("GET /api/v1/edge/sync", s.handleEdgeSync)

	// Live Mesh Topology Graph (Real-Time)
	s.mux.HandleFunc("GET /api/v1/mesh/graph", s.handleGetMeshGraph)
	s.mux.HandleFunc("GET /api/v1/topology", s.handleGetMeshGraph)

	// Microsegmentation & Access Control (Zero-Trust ACLs)
	s.mux.HandleFunc("POST /api/v1/acl/rules", s.handleCreateACLRule)
	s.mux.HandleFunc("GET /api/v1/acl/rules", s.handleListACLRules)
	s.mux.HandleFunc("DELETE /api/v1/acl/rules/{id}", s.handleDeleteACLRule)

	// Node Enrollment & Mesh Coordination
	s.mux.HandleFunc("POST /api/v1/enroll", s.handleEnrollNode)
	s.mux.HandleFunc("POST /api/v1/probes", s.handleReportProbes)
	s.mux.HandleFunc("GET /api/v1/network/{id}/peers", s.handleGetPeers)
	s.mux.HandleFunc("POST /api/v1/p2p/discover", s.handleP2PDiscover)

	// Ingress & Tunneling
	s.mux.HandleFunc("POST /api/v1/tunnels", s.handleRegisterTunnel)
	s.mux.HandleFunc("GET /api/v1/gateway/routes", s.handleGetGatewayRoutes)
	s.mux.HandleFunc("GET /api/v1/events", s.handleEventStream)

	// Real-Time WebSockets Event Hub (RFC 6455)
	s.mux.Handle("/api/v1/ws", s.wsHub.Handler())
	s.mux.Handle("/ws/v1/events", s.wsHub.Handler())

	if s.cfg.EnableGateway {
		s.mux.HandleFunc("/", s.handleGatewayFallback)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    "healthy",
		"service":   "zro-plane",
		"timestamp": time.Now(),
	})
}

// CreateNetworkRequest defines parameters for creating an overlay network.
type CreateNetworkRequest struct {
	Name      string `json:"name"`
	IPv4CIDR  string `json:"ipv4_cidr"`
	IPv6CIDR  string `json:"ipv6_cidr"`
	DNSDomain string `json:"dns_domain"`
}

func (s *Server) handleCreateNetwork(w http.ResponseWriter, r *http.Request) {
	var req CreateNetworkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.IPv4CIDR == "" {
		req.IPv4CIDR = s.cfg.DefaultCIDRv4
	}
	if req.IPv6CIDR == "" {
		req.IPv6CIDR = s.cfg.DefaultCIDRv6
	}
	if req.DNSDomain == "" {
		req.DNSDomain = "zro.internal"
	}
	if req.Name == "" {
		req.Name = "Mesh Network"
	}

	netID := core.GenerateNetworkID() // ZeroTier-style 16-hex character ID

	// Default tenant if none exists
	tenants, _ := s.db.Tenants.List(r.Context())
	var tenantID uuid.UUID
	if len(tenants) > 0 {
		tenantID = tenants[0].ID
	} else {
		tenant := &core.Tenant{
			ID:        uuid.New(),
			Name:      "Default Organization",
			Slug:      "default-org",
			APIKey:    "zro_key_" + netID,
			IsActive:  true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		_ = s.db.Tenants.Create(r.Context(), tenant)
		tenantID = tenant.ID
	}

	network := &core.Network{
		ID:        netID,
		TenantID:  tenantID,
		Name:      req.Name,
		Slug:      req.Name,
		IPv4CIDR:  req.IPv4CIDR,
		IPv6CIDR:  req.IPv6CIDR,
		DNSDomain: req.DNSDomain,
		MTU:       1420,
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.db.Networks.Create(r.Context(), network); err != nil {
		http.Error(w, fmt.Sprintf("failed to create network: %v", err), http.StatusInternalServerError)
		return
	}

	slog.Info("Created new overlay network", "id", network.ID, "name", network.Name, "cidr", network.IPv4CIDR)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(network)
}

func (s *Server) handleListNetworks(w http.ResponseWriter, r *http.Request) {
	tenants, err := s.db.Tenants.List(r.Context())
	if err != nil || len(tenants) == 0 {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]core.Network{})
		return
	}

	networks, err := s.db.Networks.ListByTenantID(r.Context(), tenants[0].ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(networks)
}

func (s *Server) handleListPoPs(w http.ResponseWriter, r *http.Request) {
	var pops []core.EdgePoP
	var err error
	if r.URL.Query().Get("all") == "true" {
		pops, err = s.db.EdgePoPs.ListAll(r.Context())
	} else {
		pops, err = s.db.EdgePoPs.ListHealthy(r.Context())
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pops)
}

// RegisterEdgePoPRequest defines dynamic registration payload from an Edge Data Plane node.
type RegisterEdgePoPRequest struct {
	PoPCode        string `json:"pop_code"`        // e.g. "KH", "SG", "US", "HK", "DE"
	Region         string `json:"region"`
	PublicEndpoint string `json:"public_endpoint"` // e.g. "173.1.1.1:51820"
	PublicKey      string `json:"public_key"`      // Curve25519 public key
	Weight         int    `json:"weight"`
	IsAnycast      bool   `json:"is_anycast"`
}

func (s *Server) handleRegisterEdgePoP(w http.ResponseWriter, r *http.Request) {
	var req RegisterEdgePoPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.PoPCode == "" || req.PublicEndpoint == "" || req.PublicKey == "" {
		http.Error(w, "pop_code, public_endpoint, and public_key are required", http.StatusBadRequest)
		return
	}

	if req.Weight <= 0 {
		req.Weight = 100
	}

	existing, _ := s.db.EdgePoPs.GetByPoPCode(r.Context(), req.PoPCode)
	var pop core.EdgePoP
	if existing != nil {
		pop = *existing
		pop.PublicEndpoint = req.PublicEndpoint
		pop.PublicKey = req.PublicKey
		pop.Region = req.Region
		pop.Weight = req.Weight
		pop.IsHealthy = true
		pop.LastSeenAt = time.Now()
		pop.UpdatedAt = time.Now()
		_ = s.db.EdgePoPs.Update(r.Context(), &pop)
	} else {
		pop = core.EdgePoP{
			ID:             uuid.New(),
			PoPCode:        req.PoPCode,
			Region:         req.Region,
			PublicEndpoint: req.PublicEndpoint,
			PublicKey:      req.PublicKey,
			Weight:         req.Weight,
			IsAnycast:      req.IsAnycast,
			IsHealthy:      true,
			LastSeenAt:     time.Now(),
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}
		_ = s.db.EdgePoPs.Create(r.Context(), &pop)
	}

	slog.Info("Edge Data Plane PoP registered dynamically", "pop_code", pop.PoPCode, "endpoint", pop.PublicEndpoint, "pubkey", pop.PublicKey)

	// Broadcast edge update
	s.broadcastDelta(map[string]any{
		"event":    "edge_registered",
		"pop_code": pop.PoPCode,
		"endpoint": pop.PublicEndpoint,
	})
	s.broadcastDelta(map[string]any{
		"event": "mesh_graph_updated",
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(pop)
}

// EdgeHeartbeatRequest defines heartbeat telemetry sent by an Edge Data Plane node.
type EdgeHeartbeatRequest struct {
	PoPCode        string  `json:"pop_code"`
	Status         string  `json:"status"` // "online"
	PeersCount     int     `json:"peers_count"`
	ActiveTunnels  int     `json:"active_tunnels"`
	RTTMs          float64 `json:"rtt_ms"`
	PublicEndpoint string  `json:"public_endpoint"`
}

func (s *Server) handleEdgeHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req EdgeHeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	pop, err := s.db.EdgePoPs.GetByPoPCode(r.Context(), req.PoPCode)
	if err != nil || pop == nil {
		http.Error(w, "pop not found", http.StatusNotFound)
		return
	}

	wasHealthy := pop.IsHealthy
	pop.IsHealthy = true
	pop.LastSeenAt = time.Now()
	pop.UpdatedAt = time.Now()
	if req.PublicEndpoint != "" {
		pop.PublicEndpoint = req.PublicEndpoint
	}
	_ = s.db.EdgePoPs.Update(r.Context(), pop)

	if !wasHealthy {
		slog.Info("Edge PoP recovered to healthy state via heartbeat", "pop_code", pop.PoPCode)
		s.broadcastDelta(map[string]any{
			"event":      "pop_status_changed",
			"pop_code":   pop.PoPCode,
			"is_healthy": true,
			"status":     "online",
		})
		s.broadcastDelta(map[string]any{
			"event": "mesh_graph_updated",
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    "acknowledged",
		"pop_code":  pop.PoPCode,
		"timestamp": time.Now(),
	})
}

func (s *Server) popWatchWorker(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pops, err := s.db.EdgePoPs.ListAll(ctx)
			if err != nil {
				continue
			}

			for _, p := range pops {
				if p.IsHealthy && !p.LastSeenAt.IsZero() && time.Since(p.LastSeenAt) > 15*time.Second {
					p.IsHealthy = false
					p.UpdatedAt = time.Now()
					_ = s.db.EdgePoPs.Update(ctx, &p)
					slog.Warn("Edge PoP heartbeat timeout - marked degraded/offline", "pop_code", p.PoPCode, "last_seen", p.LastSeenAt)
					s.broadcastDelta(map[string]any{
						"event":      "pop_status_changed",
						"pop_code":   p.PoPCode,
						"is_healthy": false,
						"status":     "offline",
					})
					s.broadcastDelta(map[string]any{
						"event": "mesh_graph_updated",
					})
				}
			}
		}
	}
}

// EdgeSyncResponse returns data plane synchronization state.
type EdgeSyncResponse struct {
	PoPs  []core.EdgePoP `json:"pops"`
	Nodes []core.Node    `json:"nodes"`
}

func (s *Server) handleEdgeSync(w http.ResponseWriter, r *http.Request) {
	pops, _ := s.db.EdgePoPs.ListHealthy(r.Context())
	var allNodes []core.Node

	// List nodes across networks
	tenants, _ := s.db.Tenants.List(r.Context())
	if len(tenants) > 0 {
		nets, _ := s.db.Networks.ListByTenantID(r.Context(), tenants[0].ID)
		for _, n := range nets {
			nodes, _ := s.db.Nodes.ListByNetworkID(r.Context(), n.ID)
			allNodes = append(allNodes, nodes...)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(EdgeSyncResponse{
		PoPs:  pops,
		Nodes: allNodes,
	})
}

// EnrollRequest payload sent by a new node attempting to join a network.
type EnrollRequest struct {
	Token        string               `json:"token"`
	PublicKey    string               `json:"public_key"`
	Hostname     string               `json:"hostname"`
	NodeType     core.NodeType        `json:"node_type"`
	Tags         core.StringList      `json:"tags"`
	Endpoints    core.StringList      `json:"endpoints"` // STUN reflexive endpoints
	AllowedPorts core.StringList      `json:"allowed_ports,omitempty"`
	DefaultDeny  *bool                `json:"default_deny,omitempty"`
	Probes       []core.LatencySample `json:"probes,omitempty"` // Parallel pre-enrollment RTT probe telemetry to PoPs
}

// EnrollResponse payload returned to the newly enrolled node.
type EnrollResponse struct {
	NodeID       uuid.UUID    `json:"node_id"`
	NetworkID    string       `json:"network_id"` // ZeroTier-style 16-hex ID
	OverlayIPv4  string       `json:"overlay_ipv4"`
	OverlayIPv6  string       `json:"overlay_ipv6"`
	DNSDomain    string       `json:"dns_domain"`
	MTU          int          `json:"mtu"`
	PrimaryPoP   core.EdgePoP `json:"primary_pop"`
	SecondaryPoP *core.EdgePoP `json:"secondary_pop,omitempty"`
	Peers        []core.Node  `json:"peers"`
}

func (s *Server) handleEnrollNode(w http.ResponseWriter, r *http.Request) {
	var req EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// High security: Verify token with public key binding
	payload, err := crypto.VerifyEnrollmentToken(s.cfg.SecretKey, req.Token, req.PublicKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("enrollment rejected (authentication failure): %v", err), http.StatusUnauthorized)
		return
	}

	network, err := s.db.Networks.GetByID(r.Context(), payload.NetworkID)
	if err != nil {
		http.Error(w, fmt.Sprintf("network %s not found", payload.NetworkID), http.StatusNotFound)
		return
	}

	// Fetch or create IPAM allocator for this network
	ipAllocator, err := s.getOrCreateIPAM(r.Context(), network)
	if err != nil {
		http.Error(w, fmt.Sprintf("IPAM initialization failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Allocate static overlay IPv4
	v4, err := ipAllocator.AllocateNext()
	if err != nil {
		http.Error(w, fmt.Sprintf("IP allocation failed: %v", err), http.StatusConflict)
		return
	}

	// Derive static overlay IPv6
	v6, err := ipam.DeriveIPv6(network.IPv6CIDR, v4)
	if err != nil {
		v6 = "::1"
	}

	nodeID := uuid.New()

	// Record any initial parallel probe samples sent during enrollment for smart delegation
	for _, p := range req.Probes {
		p.NodeID = nodeID
		if p.Timestamp.IsZero() {
			p.Timestamp = time.Now()
		}
		s.delegator.RecordProbe(p)
	}

	defaultDeny := true
	if req.DefaultDeny != nil {
		defaultDeny = *req.DefaultDeny
	}

	node := &core.Node{
		ID:           nodeID,
		NetworkID:    network.ID,
		Hostname:     req.Hostname,
		PublicKey:    req.PublicKey,
		OverlayIPv4:  v4,
		OverlayIPv6:  v6,
		NodeType:     req.NodeType,
		Tags:         req.Tags,
		AllowedIPs:   core.StringList{v4 + "/32", v6 + "/128"},
		AllowedPorts: req.AllowedPorts,
		DefaultDeny:  defaultDeny,
		Endpoints:    req.Endpoints,
		IsActive:     true,
		LastSeenAt:   time.Now(),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if node.NodeType == "" {
		node.NodeType = core.NodeTypePeer
	}

	// Delegate optimal Edge PoP
	delegationRes, err := s.delegator.Delegate(r.Context(), nodeID)
	if err == nil && delegationRes != nil {
		node.AssignedPoPID = &delegationRes.PrimaryPoP.ID
		node.AssignedPoP = &delegationRes.PrimaryPoP
	}

	if err := s.db.Nodes.Create(r.Context(), node); err != nil {
		http.Error(w, fmt.Sprintf("failed to persist node: %v", err), http.StatusInternalServerError)
		return
	}

	// Fetch other peers in this network
	peers, _ := s.db.Nodes.ListByNetworkID(r.Context(), network.ID)

	resp := EnrollResponse{
		NodeID:      node.ID,
		NetworkID:   network.ID,
		OverlayIPv4: v4,
		OverlayIPv6: v6,
		DNSDomain:   network.DNSDomain,
		MTU:         network.MTU,
		Peers:       peers,
	}

	if delegationRes != nil {
		resp.PrimaryPoP = delegationRes.PrimaryPoP
		resp.SecondaryPoP = delegationRes.SecondaryPoP
	}

	// Notify all connected edge nodes and peers of new member
	s.broadcastDelta(map[string]any{
		"event":         "node_joined",
		"network_id":    network.ID,
		"node_id":       node.ID,
		"ipv4":          node.OverlayIPv4,
		"pubkey":        node.PublicKey,
		"allowed_ports": node.AllowedPorts,
	})
	s.broadcastDelta(map[string]any{
		"event":      "mesh_graph_updated",
		"network_id": network.ID,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// P2PDiscoverRequest initiates peer-to-peer discovery and NAT reflexive signaling.
type P2PDiscoverRequest struct {
	InitiatorNodeID    uuid.UUID       `json:"initiator_node_id"`
	TargetOverlayIP    string          `json:"target_overlay_ip,omitempty"`
	TargetHostname     string          `json:"target_hostname,omitempty"`
	TargetNodeID       *uuid.UUID      `json:"target_node_id,omitempty"`
	InitiatorEndpoints core.StringList `json:"initiator_endpoints,omitempty"`
}

// P2PDiscoverResponse returns resolved target coordinates and fallback PoP relay info.
type P2PDiscoverResponse struct {
	TargetNodeID      uuid.UUID       `json:"target_node_id"`
	TargetHostname    string          `json:"target_hostname"`
	TargetPublicKey   string          `json:"target_public_key"`
	TargetOverlayIPv4 string          `json:"target_overlay_ipv4"`
	TargetOverlayIPv6 string          `json:"target_overlay_ipv6"`
	TargetEndpoints   core.StringList `json:"target_endpoints"`
	PrimaryPoP        *core.EdgePoP   `json:"primary_pop,omitempty"`
	SecondaryPoP      *core.EdgePoP   `json:"secondary_pop,omitempty"`
}

func (s *Server) handleP2PDiscover(w http.ResponseWriter, r *http.Request) {
	var req P2PDiscoverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// 1. Fetch Initiator Node
	initiator, err := s.db.Nodes.GetByID(r.Context(), req.InitiatorNodeID)
	if err != nil {
		http.Error(w, "initiator node not found", http.StatusNotFound)
		return
	}

	// Update initiator's endpoints if newer endpoints were provided
	if len(req.InitiatorEndpoints) > 0 {
		initiator.Endpoints = req.InitiatorEndpoints
		initiator.LastSeenAt = time.Now()
		_ = s.db.Nodes.Update(r.Context(), initiator)
	}

	// 2. Resolve Target Node in the same network (by Overlay IP or NodeID)
	var target *core.Node
	if req.TargetOverlayIP != "" {
		target, err = s.db.Nodes.GetByOverlayIP(r.Context(), initiator.NetworkID, req.TargetOverlayIP)
	} else if req.TargetNodeID != nil {
		target, err = s.db.Nodes.GetByID(r.Context(), *req.TargetNodeID)
	}

	if err != nil || target == nil {
		http.Error(w, "target node not found in network", http.StatusNotFound)
		return
	}

	// 3. Ensure both nodes belong to the same network (zero-trust security boundary)
	if initiator.NetworkID != target.NetworkID {
		http.Error(w, "nodes belong to different networks", http.StatusForbidden)
		return
	}

	// 4. Signal target node via delta broadcast of P2P hole punch request
	s.broadcastDelta(map[string]any{
		"event":               "p2p_punch_requested",
		"network_id":          target.NetworkID,
		"target_node_id":      target.ID,
		"initiator_node_id":   initiator.ID,
		"initiator_pubkey":    initiator.PublicKey,
		"initiator_endpoints": initiator.Endpoints,
		"initiator_overlay":   initiator.OverlayIPv4,
	})

	// 5. Construct Response
	resp := P2PDiscoverResponse{
		TargetNodeID:      target.ID,
		TargetHostname:    target.Hostname,
		TargetPublicKey:   target.PublicKey,
		TargetOverlayIPv4: target.OverlayIPv4,
		TargetOverlayIPv6: target.OverlayIPv6,
		TargetEndpoints:   target.Endpoints,
		PrimaryPoP:        target.AssignedPoP,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleReportProbes(w http.ResponseWriter, r *http.Request) {
	var sample core.LatencySample
	if err := json.NewDecoder(r.Body).Decode(&sample); err != nil {
		http.Error(w, "invalid probe payload", http.StatusBadRequest)
		return
	}

	sample.Timestamp = time.Now()
	s.delegator.RecordProbe(sample)

	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleGetPeers(w http.ResponseWriter, r *http.Request) {
	netIDStr := r.PathValue("id")
	if netIDStr == "" {
		http.Error(w, "network ID required", http.StatusBadRequest)
		return
	}

	peers, err := s.db.Nodes.ListByNetworkID(r.Context(), netIDStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(peers)
}

func (s *Server) handleRegisterTunnel(w http.ResponseWriter, r *http.Request) {
	var tunnel core.Tunnel
	if err := json.NewDecoder(r.Body).Decode(&tunnel); err != nil {
		http.Error(w, "invalid tunnel payload", http.StatusBadRequest)
		return
	}

	tunnel.ID = uuid.New()
	tunnel.CreatedAt = time.Now()
	tunnel.UpdatedAt = time.Now()

	if err := s.db.Tunnels.Create(r.Context(), &tunnel); err != nil {
		http.Error(w, fmt.Sprintf("failed to create tunnel: %v", err), http.StatusConflict)
		return
	}

	if s.cfg.EnableGateway {
		_ = s.syncInternalGateway(r.Context())
	}

	s.broadcastDelta(map[string]any{
		"event":          "gateway_routes_updated",
		"hostname":       tunnel.PublicHostname,
		"local_address":  tunnel.LocalAddress,
		"node_id":        tunnel.NodeID,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(tunnel)
}

func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan []byte, 16)
	s.subscribersMu.Lock()
	s.subscribers[ch] = true
	s.subscribersMu.Unlock()

	defer func() {
		s.subscribersMu.Lock()
		delete(s.subscribers, ch)
		close(ch)
		s.subscribersMu.Unlock()
	}()

	// Send initial heartbeat
	_, _ = fmt.Fprintf(w, "event: connected\ndata: {}\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

func (s *Server) broadcastDelta(data any) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return
	}

	// 1. Broadcast to SSE subscribers
	s.subscribersMu.RLock()
	for ch := range s.subscribers {
		select {
		case ch <- bytes:
		default:
		}
	}
	s.subscribersMu.RUnlock()

	// 2. Broadcast to real-time WebSockets hub
	var evtName string
	if m, ok := data.(map[string]any); ok {
		if ev, exists := m["event"].(string); exists {
			evtName = ev
		}
	}
	if evtName == "" {
		evtName = "delta"
	}
	if s.wsHub != nil {
		s.wsHub.Broadcast(evtName, data)
	}

	// 3. Broadcast to real-time gRPC event streams
	if s.grpcCtrl != nil {
		s.grpcCtrl.BroadcastEvent(evtName, data)
	}
}

func (s *Server) getOrCreateIPAM(ctx context.Context, net *core.Network) (*ipam.IPAM, error) {
	s.ipamMu.Lock()
	defer s.ipamMu.Unlock()

	if allocator, found := s.ipamCache[net.ID]; found {
		return allocator, nil
	}

	allocated, err := s.db.Nodes.ListAllocatedIPs(ctx, net.ID)
	if err != nil {
		return nil, err
	}

	allocator, err := ipam.NewIPAM(net.IPv4CIDR, allocated)
	if err != nil {
		return nil, err
	}

	s.ipamCache[net.ID] = allocator
	return allocator, nil
}

// GatewayBackendItem represents a single mesh node target for an exposed service.
type GatewayBackendItem struct {
	Address      string    `json:"address"` // e.g. "100.64.0.10:3000"
	NodeID       uuid.UUID `json:"node_id"`
	NodeHostname string    `json:"node_hostname"`
	Weight       int       `json:"weight"`
	Healthy      bool      `json:"healthy"`
}

// GatewayRouteItem represents a public hostname routed to a pool of mesh backends.
type GatewayRouteItem struct {
	Hostname string               `json:"hostname"`
	Protocol string               `json:"protocol"`
	Backends []GatewayBackendItem `json:"backends"`
}

// GatewayRoutesResponse returns all active routes for ingress gateways.
type GatewayRoutesResponse struct {
	Routes []GatewayRouteItem `json:"routes"`
}

func (s *Server) handleGetGatewayRoutes(w http.ResponseWriter, r *http.Request) {
	routes, err := s.buildGatewayRoutes(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to build gateway routes: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(GatewayRoutesResponse{Routes: routes})
}

func (s *Server) buildGatewayRoutes(ctx context.Context) ([]GatewayRouteItem, error) {
	tunnels, err := s.db.Tunnels.ListAll(ctx)
	if err != nil {
		return nil, err
	}

	routesMap := make(map[string]*GatewayRouteItem)

	for _, t := range tunnels {
		node, err := s.db.Nodes.GetByID(ctx, t.NodeID)
		if err != nil || node == nil || !node.IsActive || node.OverlayIPv4 == "" {
			continue
		}

		port := extractPort(t.LocalAddress)
		targetAddr := net.JoinHostPort(node.OverlayIPv4, port)

		route, exists := routesMap[t.PublicHostname]
		if !exists {
			proto := t.Protocol
			if proto == "" {
				proto = "http"
			}
			route = &GatewayRouteItem{
				Hostname: t.PublicHostname,
				Protocol: proto,
				Backends: make([]GatewayBackendItem, 0, 2),
			}
			routesMap[t.PublicHostname] = route
		}

		route.Backends = append(route.Backends, GatewayBackendItem{
			Address:      targetAddr,
			NodeID:       node.ID,
			NodeHostname: node.Hostname,
			Weight:       100,
			Healthy:      true,
		})
	}

	res := make([]GatewayRouteItem, 0, len(routesMap))
	for _, r := range routesMap {
		res = append(res, *r)
	}
	return res, nil
}

func (s *Server) syncInternalGateway(ctx context.Context) error {
	if s.gatewayProxy == nil {
		return nil
	}
	routes, err := s.buildGatewayRoutes(ctx)
	if err != nil {
		return err
	}
	for _, r := range routes {
		var bList []*balancer.Backend
		for _, b := range r.Backends {
			bList = append(bList, &balancer.Backend{
				Address: b.Address,
				Weight:  b.Weight,
				Healthy: b.Healthy,
			})
		}
		bal := balancer.NewBalancer(balancer.StrategyLatency, bList)
		s.gatewayProxy.RegisterRoute(r.Hostname, bal)
	}
	return nil
}

func (s *Server) handleGatewayFallback(w http.ResponseWriter, r *http.Request) {
	if s.gatewayProxy != nil {
		s.gatewayProxy.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}

func extractPort(addr string) string {
	if addr == "" {
		return "80"
	}
	if _, err := strconv.Atoi(addr); err == nil {
		return addr
	}
	_, port, err := net.SplitHostPort(addr)
	if err == nil && port != "" {
		return port
	}
	return "80"
}

// MeshGraphNode represents a vertex in the real-time mesh topology graph.
type MeshGraphNode struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"` // "edge", "gateway", "peer"
	Hostname     string    `json:"hostname"`
	OverlayIPv4  string    `json:"overlay_ipv4,omitempty"`
	OverlayIPv6  string    `json:"overlay_ipv6,omitempty"`
	Endpoint     string    `json:"endpoint,omitempty"`
	PublicKey    string    `json:"public_key,omitempty"`
	Status       string    `json:"status"` // "online", "offline"
	AssignedPoP  string    `json:"assigned_pop,omitempty"`
	Tags         []string  `json:"tags,omitempty"`
	AllowedPorts []string  `json:"allowed_ports,omitempty"`
	DefaultDeny  bool      `json:"default_deny"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	Tunnels      []string  `json:"tunnels,omitempty"`
}

// MeshGraphEdge represents a directed connection/link in the mesh graph.
type MeshGraphEdge struct {
	ID      string  `json:"id"`
	Source  string  `json:"source"`
	Target  string  `json:"target"`
	Type    string  `json:"type"` // "backbone_link", "edge_mesh", "p2p_direct", "gateway_proxy"
	Status  string  `json:"status"` // "active", "degraded", "idle"
	RTTMs   float64 `json:"rtt_ms,omitempty"`
	Details string  `json:"details,omitempty"`
}

// MeshGraphResponse returns the complete real-time topology of the mesh.
type MeshGraphResponse struct {
	NetworkID string          `json:"network_id"`
	Timestamp time.Time       `json:"timestamp"`
	Nodes     []MeshGraphNode `json:"nodes"`
	Edges     []MeshGraphEdge `json:"edges"`
	Stats     map[string]any  `json:"stats"`
}

func (s *Server) handleGetMeshGraph(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	netID := r.URL.Query().Get("network_id")

	// If no network_id provided, pick first available network
	if netID == "" {
		tenants, _ := s.db.Tenants.List(ctx)
		if len(tenants) > 0 {
			nets, _ := s.db.Networks.ListByTenantID(ctx, tenants[0].ID)
			if len(nets) > 0 {
				netID = nets[0].ID
			}
		}
	}

	var graphNodes []MeshGraphNode
	var graphEdges []MeshGraphEdge

	// 1. Edge PoPs
	pops, _ := s.db.EdgePoPs.ListAll(ctx)
	for _, p := range pops {
		status := "offline"
		if p.IsHealthy && (p.LastSeenAt.IsZero() || time.Since(p.LastSeenAt) < 20*time.Second) {
			status = "online"
		}
		graphNodes = append(graphNodes, MeshGraphNode{
			ID:          "pop-" + p.PoPCode,
			Type:        "edge",
			Hostname:    "pop-" + p.PoPCode,
			Endpoint:    p.PublicEndpoint,
			PublicKey:   p.PublicKey,
			Status:      status,
			LastSeenAt:  p.LastSeenAt,
			AssignedPoP: p.PoPCode,
		})
	}

	// Connect Edge PoP backbones (inter-PoP mesh backbone links)
	for i := 0; i < len(pops); i++ {
		for j := i + 1; j < len(pops); j++ {
			graphEdges = append(graphEdges, MeshGraphEdge{
				ID:     fmt.Sprintf("backbone-%s-%s", pops[i].PoPCode, pops[j].PoPCode),
				Source: "pop-" + pops[i].PoPCode,
				Target: "pop-" + pops[j].PoPCode,
				Type:   "edge_mesh",
				Status: "active",
				RTTMs:  15.0,
			})
		}
	}

	// 2. Nodes in network
	var nodes []core.Node
	if netID != "" {
		nodes, _ = s.db.Nodes.ListByNetworkID(ctx, netID)
	}

	onlineCount := 0
	for _, n := range nodes {
		status := "offline"
		if time.Since(n.LastSeenAt) < 60*time.Second {
			status = "online"
			onlineCount++
		}

		tunnels, _ := s.db.Tunnels.ListByNodeID(ctx, n.ID)
		var tunNames []string
		for _, t := range tunnels {
			tunNames = append(tunNames, t.PublicHostname+" -> "+t.LocalAddress)
		}

		assignedCode := ""
		if n.AssignedPoP != nil {
			assignedCode = n.AssignedPoP.PoPCode
		} else if n.AssignedPoPID != nil {
			for _, p := range pops {
				if p.ID == *n.AssignedPoPID {
					assignedCode = p.PoPCode
					break
				}
			}
		}

		nodeTypeStr := string(n.NodeType)
		if nodeTypeStr == "" {
			nodeTypeStr = "peer"
		}

		graphNodes = append(graphNodes, MeshGraphNode{
			ID:           n.ID.String(),
			Type:         nodeTypeStr,
			Hostname:     n.Hostname,
			OverlayIPv4:  n.OverlayIPv4,
			OverlayIPv6:  n.OverlayIPv6,
			PublicKey:    n.PublicKey,
			Status:       status,
			AssignedPoP:  assignedCode,
			Tags:         []string(n.Tags),
			AllowedPorts: []string(n.AllowedPorts),
			DefaultDeny:  n.DefaultDeny,
			LastSeenAt:   n.LastSeenAt,
			Tunnels:      tunNames,
		})

		// Edge from node to its assigned Edge PoP
		if assignedCode != "" {
			graphEdges = append(graphEdges, MeshGraphEdge{
				ID:     fmt.Sprintf("link-%s-pop-%s", n.Hostname, assignedCode),
				Source: n.Hostname,
				Target: "pop-" + assignedCode,
				Type:   "backbone_link",
				Status: status,
				RTTMs:  5.0,
			})
		}

		// Gateway-to-node routes
		if len(tunnels) > 0 {
			for _, t := range tunnels {
				graphEdges = append(graphEdges, MeshGraphEdge{
					ID:      fmt.Sprintf("gw-route-%s-%s", t.PublicHostname, n.Hostname),
					Source:  "gateway",
					Target:  n.Hostname,
					Type:    "gateway_proxy",
					Status:  "active",
					Details: t.PublicHostname + " -> " + n.OverlayIPv4 + " (" + t.LocalAddress + ")",
				})
			}
		}
	}

	// 3. Add direct P2P edges between active peer nodes
	for i := 0; i < len(nodes); i++ {
		for j := i + 1; j < len(nodes); j++ {
			n1 := nodes[i]
			n2 := nodes[j]
			if n1.NodeType == core.NodeTypePeer && n2.NodeType == core.NodeTypePeer {
				graphEdges = append(graphEdges, MeshGraphEdge{
					ID:     fmt.Sprintf("p2p-%s-%s", n1.Hostname, n2.Hostname),
					Source: n1.Hostname,
					Target: n2.Hostname,
					Type:   "p2p_direct",
					Status: "active",
					RTTMs:  12.0,
				})
			}
		}
	}

	resp := MeshGraphResponse{
		NetworkID: netID,
		Timestamp: time.Now(),
		Nodes:     graphNodes,
		Edges:     graphEdges,
		Stats: map[string]any{
			"total_nodes":  len(graphNodes),
			"online_nodes": onlineCount,
			"total_edges":  len(graphEdges),
			"edge_pops":    len(pops),
			"network_id":   netID,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// CreateACLRuleRequest defines parameters for a new microsegmentation rule.
type CreateACLRuleRequest struct {
	NetworkID string         `json:"network_id"`
	Priority  int            `json:"priority"`
	SourceIP  string         `json:"source_ip"`
	DestIP    string         `json:"dest_ip"`
	SourceTag string         `json:"source_tag"`
	DestTag   string         `json:"dest_tag"`
	Protocol  string         `json:"protocol"`
	Ports     string         `json:"ports"`
	Action    core.ACLAction `json:"action"`
}

func (s *Server) handleCreateACLRule(w http.ResponseWriter, r *http.Request) {
	var req CreateACLRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.NetworkID == "" {
		http.Error(w, "network_id is required", http.StatusBadRequest)
		return
	}

	if req.Priority <= 0 {
		req.Priority = 100
	}
	if req.Action == "" {
		req.Action = core.ACLActionAllow
	}
	if req.Protocol == "" {
		req.Protocol = "*"
	}
	if req.Ports == "" {
		req.Ports = "*"
	}
	if req.SourceIP == "" {
		req.SourceIP = "*"
	}
	if req.DestIP == "" {
		req.DestIP = "*"
	}
	if req.SourceTag == "" {
		req.SourceTag = "*"
	}
	if req.DestTag == "" {
		req.DestTag = "*"
	}

	rule := &core.ACLRule{
		ID:        uuid.New(),
		NetworkID: req.NetworkID,
		Priority:  req.Priority,
		SourceIP:  req.SourceIP,
		DestIP:    req.DestIP,
		SourceTag: req.SourceTag,
		DestTag:   req.DestTag,
		Protocol:  req.Protocol,
		Ports:     req.Ports,
		Action:    req.Action,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.db.ACLs.Create(r.Context(), rule); err != nil {
		http.Error(w, fmt.Sprintf("failed to create ACL rule: %v", err), http.StatusInternalServerError)
		return
	}

	slog.Info("Created new ACL rule", "id", rule.ID, "network_id", rule.NetworkID, "action", rule.Action, "ports", rule.Ports)

	// Broadcast ACL and graph update
	s.broadcastDelta(map[string]any{
		"event":      "acl_rules_updated",
		"network_id": rule.NetworkID,
		"rule_id":    rule.ID,
	})
	s.broadcastDelta(map[string]any{
		"event": "mesh_graph_updated",
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(rule)
}

func (s *Server) handleListACLRules(w http.ResponseWriter, r *http.Request) {
	netID := r.URL.Query().Get("network_id")
	if netID == "" {
		http.Error(w, "network_id query parameter is required", http.StatusBadRequest)
		return
	}

	rules, err := s.db.ACLs.ListByNetworkID(r.Context(), netID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rules)
}

func (s *Server) handleDeleteACLRule(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid rule id", http.StatusBadRequest)
		return
	}

	if err := s.db.ACLs.Delete(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.broadcastDelta(map[string]any{
		"event":   "acl_rules_updated",
		"rule_id": idStr,
	})
	s.broadcastDelta(map[string]any{
		"event": "mesh_graph_updated",
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}
