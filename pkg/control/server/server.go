package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/cubis/zro/pkg/config"
	"github.com/cubis/zro/pkg/control/delegation"
	"github.com/cubis/zro/pkg/control/ipam"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/crypto"
	"github.com/cubis/zro/pkg/store"
	"github.com/google/uuid"
)

// Server is the HTTP/REST Control Plane API server for ZRO.
type Server struct {
	cfg        *config.ControlPlaneConfig
	db         *store.DB
	delegator  *delegation.Engine
	ipamCache  map[uuid.UUID]*ipam.IPAM
	ipamMu     sync.RWMutex
	httpServer *http.Server
	mux        *http.ServeMux

	// Notification subscribers for delta updates
	subscribersMu sync.RWMutex
	subscribers   map[chan []byte]bool
}

// NewServer creates a new instance of the Control Plane API Server.
func NewServer(cfg *config.ControlPlaneConfig, db *store.DB) *Server {
	delegator := delegation.NewEngine(db.EdgePoPs)
	mux := http.NewServeMux()

	s := &Server{
		cfg:         cfg,
		db:          db,
		delegator:   delegator,
		ipamCache:   make(map[uuid.UUID]*ipam.IPAM),
		mux:         mux,
		subscribers: make(map[chan []byte]bool),
	}

	s.registerRoutes()
	return s
}

// Start begins listening on the configured address.
func (s *Server) Start() error {
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
	s.mux.HandleFunc("GET /api/v1/pops", s.handleListPoPs)
	s.mux.HandleFunc("POST /api/v1/enroll", s.handleEnrollNode)
	s.mux.HandleFunc("POST /api/v1/probes", s.handleReportProbes)
	s.mux.HandleFunc("GET /api/v1/network/{id}/peers", s.handleGetPeers)
	s.mux.HandleFunc("POST /api/v1/tunnels", s.handleRegisterTunnel)
	s.mux.HandleFunc("GET /api/v1/events", s.handleEventStream)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    "healthy",
		"service":   "zro-plane",
		"timestamp": time.Now(),
	})
}

func (s *Server) handleListPoPs(w http.ResponseWriter, r *http.Request) {
	pops, err := s.db.EdgePoPs.ListHealthy(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pops)
}

// EnrollRequest payload sent by a new node attempting to join a network.
type EnrollRequest struct {
	Token       string          `json:"token"`
	PublicKey   string          `json:"public_key"`
	Hostname    string          `json:"hostname"`
	NodeType    core.NodeType   `json:"node_type"`
	Tags        core.StringList `json:"tags"`
	Endpoints   core.StringList `json:"endpoints"` // STUN reflexive endpoints
}

// EnrollResponse payload returned to the newly enrolled node.
type EnrollResponse struct {
	NodeID       uuid.UUID                `json:"node_id"`
	NetworkID    uuid.UUID                `json:"network_id"`
	OverlayIPv4  string                   `json:"overlay_ipv4"`
	OverlayIPv6  string                   `json:"overlay_ipv6"`
	DNSDomain    string                   `json:"dns_domain"`
	MTU          int                      `json:"mtu"`
	PrimaryPoP   core.EdgePoP             `json:"primary_pop"`
	SecondaryPoP *core.EdgePoP            `json:"secondary_pop,omitempty"`
	Peers        []core.Node              `json:"peers"`
}

func (s *Server) handleEnrollNode(w http.ResponseWriter, r *http.Request) {
	var req EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	payload, err := crypto.VerifyEnrollmentToken(s.cfg.SecretKey, req.Token)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid or expired token: %v", err), http.StatusUnauthorized)
		return
	}

	netUUID, err := uuid.Parse(payload.NetworkID)
	if err != nil {
		http.Error(w, "invalid network ID in token", http.StatusBadRequest)
		return
	}

	network, err := s.db.Networks.GetByID(r.Context(), netUUID)
	if err != nil {
		http.Error(w, "network not found", http.StatusNotFound)
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
	node := &core.Node{
		ID:          nodeID,
		NetworkID:   netUUID,
		Hostname:    req.Hostname,
		PublicKey:   req.PublicKey,
		OverlayIPv4: v4,
		OverlayIPv6: v6,
		NodeType:    req.NodeType,
		Tags:        req.Tags,
		AllowedIPs:  core.StringList{v4 + "/32", v6 + "/128"},
		Endpoints:   req.Endpoints,
		IsActive:    true,
		LastSeenAt:  time.Now(),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
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
	peers, _ := s.db.Nodes.ListByNetworkID(r.Context(), netUUID)

	resp := EnrollResponse{
		NodeID:      node.ID,
		NetworkID:   netUUID,
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
		"event":   "node_joined",
		"node_id": node.ID,
		"ipv4":    node.OverlayIPv4,
		"pubkey":  node.PublicKey,
	})

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
	netUUID, err := uuid.Parse(netIDStr)
	if err != nil {
		http.Error(w, "invalid network ID", http.StatusBadRequest)
		return
	}

	peers, err := s.db.Nodes.ListByNetworkID(r.Context(), netUUID)
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

	s.broadcastDelta(map[string]any{
		"event":           "tunnel_registered",
		"hostname":        tunnel.PublicHostname,
		"local_address":   tunnel.LocalAddress,
		"node_id":         tunnel.NodeID,
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

	s.subscribersMu.RLock()
	defer s.subscribersMu.RUnlock()

	for ch := range s.subscribers {
		select {
		case ch <- bytes:
		default:
		}
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
