// Package service holds the control plane's node-facing business logic. The
// REST and gRPC servers are thin adapters over it, so authorization, IPAM and
// event rules are implemented exactly once.
package service

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cubis/zro/pkg/config"
	controlauth "github.com/cubis/zro/pkg/control/auth"
	"github.com/cubis/zro/pkg/control/delegation"
	"github.com/cubis/zro/pkg/control/enroll"
	"github.com/cubis/zro/pkg/control/events"
	"github.com/cubis/zro/pkg/control/ipam"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/store"
	"github.com/google/uuid"
)

// Service implements enrollment, probing, P2P discovery, tunnels and routing.
type Service struct {
	cfg       *config.ControlPlaneConfig
	db        *store.DB
	bus       *events.Bus
	delegator *delegation.Engine

	ipamMu    sync.Mutex
	ipamCache map[string]*ipam.IPAM // network ID -> allocator
}

// New creates a Service publishing change events to bus.
func New(cfg *config.ControlPlaneConfig, db *store.DB, bus *events.Bus) *Service {
	return &Service{
		cfg:       cfg,
		db:        db,
		bus:       bus,
		delegator: delegation.NewEngine(db.EdgePoPs),
		ipamCache: make(map[string]*ipam.IPAM),
	}
}

// Delegator exposes the shared smart-routing engine (probe history, PoP health).
func (s *Service) Delegator() *delegation.Engine { return s.delegator }

// publish emits a change event limited to scope; data also carries the event name.
func (s *Service) publish(scope events.Scope, name string, data map[string]any) {
	data["event"] = name
	s.bus.Publish(scope, name, data)
}

// --- Enrollment ---------------------------------------------------------

// EnrollRequest is sent by a node, gateway or edge joining a network.
type EnrollRequest struct {
	Token        string               `json:"token"`
	PublicKey    string               `json:"public_key"`
	Hostname     string               `json:"hostname"`
	NodeType     core.NodeType        `json:"node_type"`
	Tags         core.StringList      `json:"tags"`
	Endpoints    core.StringList      `json:"endpoints"` // STUN reflexive endpoints
	AllowedPorts core.StringList      `json:"allowed_ports,omitempty"`
	DefaultDeny  *bool                `json:"default_deny,omitempty"`
	Probes       []core.LatencySample `json:"probes,omitempty"` // pre-enrollment RTT telemetry
}

// EnrollResponse is returned to the newly enrolled node.
type EnrollResponse struct {
	NodeID       uuid.UUID       `json:"node_id"`
	NetworkID    string          `json:"network_id"` // ZeroTier-style 16-hex ID
	NodeToken    string          `json:"node_token"` // bearer token for node-facing APIs
	OverlayIPv4  string          `json:"overlay_ipv4"`
	OverlayIPv6  string          `json:"overlay_ipv6"`
	DNSDomain    string          `json:"dns_domain"`
	MTU          int             `json:"mtu"`
	AllowedIPs   core.StringList `json:"allowed_ips"`
	AllowedPorts core.StringList `json:"allowed_ports"`
	DefaultDeny  bool            `json:"default_deny"`
	PrimaryPoP   core.EdgePoP    `json:"primary_pop"`
	SecondaryPoP *core.EdgePoP   `json:"secondary_pop,omitempty"`
	Peers        []core.Node     `json:"peers"`
}

// Enroll verifies the token and admits the node into its network.
func (s *Service) Enroll(ctx context.Context, req EnrollRequest) (*EnrollResponse, error) {
	grant, err := enroll.Authorize(ctx, s.cfg.SecretKey, s.db.Enrollments, enroll.Request{
		Token: req.Token, PublicKey: req.PublicKey, Hostname: req.Hostname, NodeType: req.NodeType,
	})
	if err != nil {
		switch {
		case errors.Is(err, enroll.ErrUnauthenticated):
			return nil, &Error{Kind: KindUnauthenticated, Msg: err.Error()}
		case errors.Is(err, enroll.ErrForbidden):
			return nil, &Error{Kind: KindForbidden, Msg: err.Error()}
		case errors.Is(err, enroll.ErrConflict):
			return nil, &Error{Kind: KindConflict, Msg: err.Error()}
		}
		return nil, internal("enrollment failed", err)
	}

	network, err := s.db.Networks.GetByID(ctx, grant.NetworkID)
	if err != nil || network == nil {
		return nil, newErr(KindNotFound, "network %s not found", grant.NetworkID)
	}
	if !network.IsActive {
		return nil, newErr(KindForbidden, "network is inactive")
	}

	allocator, err := s.allocator(ctx, network)
	if err != nil {
		return nil, internal("IPAM initialization failed", err)
	}
	v4, err := allocator.AllocateNext()
	if err != nil {
		return nil, newErr(KindExhausted, "IP allocation failed: %v", err)
	}
	persisted := false
	defer func() {
		if !persisted { // give the address back if anything below fails
			allocator.Release(v4)
		}
	}()

	v6, err := ipam.DeriveIPv6(network.IPv6CIDR, v4)
	if err != nil {
		return nil, internal("IPv6 derivation failed", err)
	}

	token, tokenHash, err := controlauth.GenerateToken("zro_node_")
	if err != nil {
		return nil, internal("failed to generate node credentials", err)
	}

	nodeID := uuid.New()
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

	now := time.Now()
	node := &core.Node{
		ID:           nodeID,
		NetworkID:    network.ID,
		Hostname:     grant.Hostname,
		PublicKey:    req.PublicKey,
		TokenHash:    tokenHash,
		OverlayIPv4:  v4,
		OverlayIPv6:  v6,
		NodeType:     grant.NodeType,
		Tags:         req.Tags,
		AllowedIPs:   core.StringList{v4 + "/32", v6 + "/128"},
		AllowedPorts: req.AllowedPorts,
		DefaultDeny:  defaultDeny,
		Endpoints:    req.Endpoints,
		IsActive:     true,
		LastSeenAt:   now,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	delegationRes, err := s.delegator.Delegate(ctx, nodeID)
	if err == nil && delegationRes != nil {
		node.AssignedPoPID = &delegationRes.PrimaryPoP.ID
		node.AssignedPoP = &delegationRes.PrimaryPoP
	}

	if err := s.db.Nodes.Create(ctx, node); err != nil {
		return nil, internal("failed to persist node", err)
	}
	persisted = true

	peers, _ := s.db.Nodes.ListByNetworkID(ctx, network.ID)
	resp := &EnrollResponse{
		NodeID:       node.ID,
		NetworkID:    network.ID,
		NodeToken:    token,
		OverlayIPv4:  v4,
		OverlayIPv6:  v6,
		DNSDomain:    network.DNSDomain,
		MTU:          network.MTU,
		AllowedIPs:   node.AllowedIPs,
		AllowedPorts: node.AllowedPorts,
		DefaultDeny:  node.DefaultDeny,
		Peers:        peers,
	}
	if delegationRes != nil {
		resp.PrimaryPoP = delegationRes.PrimaryPoP
		resp.SecondaryPoP = delegationRes.SecondaryPoP
	}

	scope := events.OfNetwork(network)
	s.publish(scope, "node_joined", map[string]any{
		"network_id":    network.ID,
		"node_id":       node.ID,
		"ipv4":          node.OverlayIPv4,
		"pubkey":        node.PublicKey,
		"allowed_ports": node.AllowedPorts,
	})
	s.publish(scope, "mesh_graph_updated", map[string]any{"network_id": network.ID})
	return resp, nil
}

// allocator returns the cached IPAM allocator for a network.
func (s *Service) allocator(ctx context.Context, n *core.Network) (*ipam.IPAM, error) {
	s.ipamMu.Lock()
	defer s.ipamMu.Unlock()

	if a, ok := s.ipamCache[n.ID]; ok {
		return a, nil
	}
	allocated, err := s.db.Nodes.ListAllocatedIPs(ctx, n.ID)
	if err != nil {
		return nil, err
	}
	a, err := ipam.NewIPAM(n.IPv4CIDR, allocated)
	if err != nil {
		return nil, err
	}
	s.ipamCache[n.ID] = a
	return a, nil
}

// --- Probes -------------------------------------------------------------

// ReportProbe records a latency sample for node and returns its current
// primary PoP code ("" if none qualifies).
func (s *Service) ReportProbe(ctx context.Context, node *core.Node, sample core.LatencySample) string {
	sample.NodeID = node.ID // never trust a caller-supplied node ID
	sample.Timestamp = time.Now()
	s.delegator.RecordProbe(sample)
	if res, err := s.delegator.Delegate(ctx, node.ID); err == nil && res != nil {
		return res.PrimaryPoP.PoPCode
	}
	return ""
}

// --- P2P discovery ------------------------------------------------------

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

// DiscoverP2P resolves a target in the initiator's own network and signals it
// to start hole punching. The initiator is the authenticated node.
func (s *Service) DiscoverP2P(ctx context.Context, initiator *core.Node, req P2PDiscoverRequest) (*P2PDiscoverResponse, error) {
	if req.InitiatorNodeID != uuid.Nil && req.InitiatorNodeID != initiator.ID {
		return nil, newErr(KindForbidden, "initiator node does not match authenticated node")
	}

	if len(req.InitiatorEndpoints) > 0 {
		initiator.Endpoints = req.InitiatorEndpoints
		initiator.LastSeenAt = time.Now()
		_ = s.db.Nodes.Update(ctx, initiator)
	}

	var target *core.Node
	var err error
	switch {
	case req.TargetOverlayIP != "":
		target, err = s.db.Nodes.GetByOverlayIP(ctx, initiator.NetworkID, req.TargetOverlayIP)
	case req.TargetNodeID != nil:
		target, err = s.db.Nodes.GetByID(ctx, *req.TargetNodeID)
	}
	// A target in another network is indistinguishable from a missing one.
	if err != nil || target == nil || target.NetworkID != initiator.NetworkID {
		return nil, newErr(KindNotFound, "target node not found in network")
	}

	s.publish(s.scopeForNetwork(ctx, target.NetworkID), "p2p_punch_requested", map[string]any{
		"network_id":          target.NetworkID,
		"target_node_id":      target.ID,
		"initiator_node_id":   initiator.ID,
		"initiator_pubkey":    initiator.PublicKey,
		"initiator_endpoints": initiator.Endpoints,
		"initiator_overlay":   initiator.OverlayIPv4,
	})

	return &P2PDiscoverResponse{
		TargetNodeID:      target.ID,
		TargetHostname:    target.Hostname,
		TargetPublicKey:   target.PublicKey,
		TargetOverlayIPv4: target.OverlayIPv4,
		TargetOverlayIPv6: target.OverlayIPv6,
		TargetEndpoints:   target.Endpoints,
		PrimaryPoP:        target.AssignedPoP,
	}, nil
}

// scopeForNetwork resolves a network's event scope; if it cannot be loaded the
// event is scoped to the network ID only so tenant subscribers never see it.
func (s *Service) scopeForNetwork(ctx context.Context, networkID string) events.Scope {
	if n, err := s.db.Networks.GetByID(ctx, networkID); err == nil && n != nil {
		return events.OfNetwork(n)
	}
	return events.Scope{NetworkID: networkID}
}

// --- Tunnels ------------------------------------------------------------

// hostnameRE matches an RFC 1123 DNS name (lower-case, dot-separated labels).
var hostnameRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func validateTunnel(t *core.Tunnel) error {
	t.PublicHostname = strings.ToLower(strings.TrimSpace(t.PublicHostname))
	if len(t.PublicHostname) > 253 || !hostnameRE.MatchString(t.PublicHostname) {
		return errors.New("public_hostname must be a valid DNS name")
	}
	host, port, err := net.SplitHostPort(t.LocalAddress)
	if err != nil || host == "" {
		return errors.New("local_address must be host:port")
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return errors.New("local_address has an invalid port")
	}
	switch t.Protocol {
	case "":
		t.Protocol = "http"
	case "http", "tcp", "grpc":
	default:
		return errors.New("protocol must be http, tcp or grpc")
	}
	if t.Name == "" {
		t.Name = t.PublicHostname
	}
	return nil
}

// RegisterTunnel exposes a local service of node under a public hostname.
// Ownership comes from node; a hostname belongs to a single network, though
// nodes of that network may share it for load balancing.
func (s *Service) RegisterTunnel(ctx context.Context, node *core.Node, req core.Tunnel) (*core.Tunnel, error) {
	if err := validateTunnel(&req); err != nil {
		return nil, &Error{Kind: KindInvalid, Msg: err.Error()}
	}
	network, err := s.db.Networks.GetByID(ctx, node.NetworkID)
	if err != nil || network == nil {
		return nil, newErr(KindNotFound, "network not found")
	}

	existing, err := s.db.Tunnels.ListByHostname(ctx, req.PublicHostname)
	if err != nil {
		return nil, internal("failed to check hostname", err)
	}
	for _, t := range existing {
		if t.NetworkID != network.ID {
			return nil, newErr(KindConflict, "hostname is already in use")
		}
	}

	now := time.Now()
	tunnel := &core.Tunnel{
		ID:             uuid.New(),
		NodeID:         node.ID,
		TenantID:       network.TenantID,
		NetworkID:      network.ID,
		Name:           req.Name,
		LocalAddress:   req.LocalAddress,
		PublicHostname: req.PublicHostname,
		Protocol:       req.Protocol,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.db.Tunnels.Create(ctx, tunnel); err != nil {
		return nil, newErr(KindConflict, "failed to create tunnel")
	}

	s.publish(events.OfNetwork(network), "gateway_routes_updated", map[string]any{
		"network_id":    network.ID,
		"hostname":      tunnel.PublicHostname,
		"local_address": tunnel.LocalAddress,
		"node_id":       tunnel.NodeID,
	})
	return tunnel, nil
}

// ListTunnels returns the tunnels of node's network.
func (s *Service) ListTunnels(ctx context.Context, node *core.Node) ([]core.Tunnel, error) {
	tunnels, err := s.db.Tunnels.ListByNetworkID(ctx, node.NetworkID)
	if err != nil {
		return nil, internal("failed to list tunnels", err)
	}
	return tunnels, nil
}

// DeleteTunnel removes a tunnel owned by node.
func (s *Service) DeleteTunnel(ctx context.Context, node *core.Node, id uuid.UUID) error {
	tunnel, err := s.db.Tunnels.GetByID(ctx, id)
	if err != nil || tunnel == nil || tunnel.NodeID != node.ID {
		return newErr(KindNotFound, "tunnel not found")
	}
	if err := s.db.Tunnels.Delete(ctx, id); err != nil {
		return internal("failed to delete tunnel", err)
	}
	s.publish(s.scopeForNetwork(ctx, node.NetworkID), "gateway_routes_updated", map[string]any{
		"network_id": node.NetworkID,
		"hostname":   tunnel.PublicHostname,
	})
	return nil
}

// --- Gateway routes -----------------------------------------------------

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

// GatewayRoutes groups tunnels into per-hostname routes. An empty networkID
// covers every network and is reserved for the plane's embedded gateway.
func (s *Service) GatewayRoutes(ctx context.Context, networkID string) ([]GatewayRouteItem, error) {
	var tunnels []core.Tunnel
	var err error
	if networkID == "" {
		tunnels, err = s.db.Tunnels.ListAll(ctx)
	} else {
		tunnels, err = s.db.Tunnels.ListByNetworkID(ctx, networkID)
	}
	if err != nil {
		return nil, internal("failed to list tunnels", err)
	}

	nodes := make(map[uuid.UUID]*core.Node)
	routes := make(map[string]*GatewayRouteItem)
	var order []string

	for _, t := range tunnels {
		node, cached := nodes[t.NodeID]
		if !cached {
			node, _ = s.db.Nodes.GetByID(ctx, t.NodeID)
			nodes[t.NodeID] = node
		}
		if node == nil || !node.IsActive || node.OverlayIPv4 == "" {
			continue
		}

		route, exists := routes[t.PublicHostname]
		if !exists {
			proto := t.Protocol
			if proto == "" {
				proto = "http"
			}
			route = &GatewayRouteItem{Hostname: t.PublicHostname, Protocol: proto, Backends: make([]GatewayBackendItem, 0, 2)}
			routes[t.PublicHostname] = route
			order = append(order, t.PublicHostname)
		}
		route.Backends = append(route.Backends, GatewayBackendItem{
			Address:      net.JoinHostPort(node.OverlayIPv4, portOf(t.LocalAddress)),
			NodeID:       node.ID,
			NodeHostname: node.Hostname,
			Weight:       100,
			Healthy:      true,
		})
	}

	res := make([]GatewayRouteItem, 0, len(routes))
	for _, h := range order {
		res = append(res, *routes[h])
	}
	return res, nil
}

// portOf returns the port of host:port, falling back to the whole string.
func portOf(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return port
	}
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[i+1:]
	}
	return addr
}

// --- Edge sync ----------------------------------------------------------

// EdgeSync returns healthy PoPs and every node in the mesh. Edge PoPs are
// global infrastructure, so this spans all tenants and must only be offered to
// an edge principal.
func (s *Service) EdgeSync(ctx context.Context) ([]core.EdgePoP, []core.Node, error) {
	pops, err := s.db.EdgePoPs.ListHealthy(ctx)
	if err != nil {
		return nil, nil, internal("failed to list pops", err)
	}
	tenants, err := s.db.Tenants.List(ctx)
	if err != nil {
		return nil, nil, internal("failed to list tenants", err)
	}
	var nodes []core.Node
	for _, t := range tenants {
		nets, _ := s.db.Networks.ListByTenantID(ctx, t.ID)
		for _, n := range nets {
			ns, _ := s.db.Nodes.ListByNetworkID(ctx, n.ID)
			nodes = append(nodes, ns...)
		}
	}
	return pops, nodes, nil
}
