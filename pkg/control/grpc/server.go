package grpc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	v1 "github.com/cubis/zro/api/proto/v1"
	"github.com/cubis/zro/pkg/config"
	"github.com/cubis/zro/pkg/control/delegation"
	"github.com/cubis/zro/pkg/control/enroll"
	"github.com/cubis/zro/pkg/control/events"
	"github.com/cubis/zro/pkg/control/ipam"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/store"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements the ControlPlaneServiceServer for gRPC.
type Server struct {
	v1.UnimplementedControlPlaneServiceServer
	cfg       *config.ControlPlaneConfig
	db        *store.DB
	delegator *delegation.Engine
	ipamCache map[string]*ipam.IPAM
	ipamMu    sync.RWMutex

	bus         *events.Bus
	streamScope func(context.Context) (events.Scope, error)
}

// NewServer creates a new gRPC Control Plane Server.
func NewServer(cfg *config.ControlPlaneConfig, db *store.DB) *Server {
	return &Server{
		cfg:       cfg,
		db:        db,
		delegator: delegation.NewEngine(db.EdgePoPs),
		ipamCache: make(map[string]*ipam.IPAM),
		bus:       events.NewBus(),
		streamScope: func(context.Context) (events.Scope, error) {
			return events.Scope{}, status.Error(codes.Unauthenticated, "event streams are not configured")
		},
	}
}

// SetEventSource wires the shared event bus and the function that decides
// which events an incoming stream may see. Streams fail closed until set.
func (s *Server) SetEventSource(bus *events.Bus, scope func(context.Context) (events.Scope, error)) {
	s.bus, s.streamScope = bus, scope
}

// Enroll handles cryptographic node and gateway enrollment over gRPC.
func (s *Server) Enroll(ctx context.Context, req *v1.EnrollRequest) (*v1.EnrollResponse, error) {
	grant, err := enroll.Authorize(ctx, s.cfg.SecretKey, s.db.Enrollments, enroll.Request{
		Token: req.Token, PublicKey: req.PublicKey, Hostname: req.Hostname, NodeType: core.NodeType(req.NodeType),
	})
	if err != nil {
		switch {
		case errors.Is(err, enroll.ErrUnauthenticated):
			return nil, status.Error(codes.Unauthenticated, err.Error())
		case errors.Is(err, enroll.ErrForbidden):
			return nil, status.Error(codes.PermissionDenied, err.Error())
		case errors.Is(err, enroll.ErrConflict):
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		return nil, status.Error(codes.Internal, "enrollment failed")
	}

	network, err := s.db.Networks.GetByID(ctx, grant.NetworkID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "network %s not found", grant.NetworkID)
	}

	allocator, err := s.getOrCreateIPAM(ctx, network)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "IPAM initialization failed: %v", err)
	}

	v4, err := allocator.AllocateNext()
	if err != nil {
		return nil, status.Errorf(codes.ResourceExhausted, "IP allocation failed: %v", err)
	}

	v6, err := ipam.DeriveIPv6(network.IPv6CIDR, v4)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "IPv6 derivation failed: %v", err)
	}

	nodeID := uuid.New()
	for _, p := range req.Probes {
		s.delegator.RecordProbe(core.LatencySample{
			NodeID:     nodeID,
			PoPCode:    p.PopCode,
			RTT:        time.Duration(p.RttNs),
			PacketLoss: p.PacketLoss,
			Timestamp:  time.Now(),
		})
	}

	node := &core.Node{
		ID:          nodeID,
		NetworkID:   network.ID,
		Hostname:    grant.Hostname,
		PublicKey:   req.PublicKey,
		OverlayIPv4: v4,
		OverlayIPv6: v6,
		NodeType:    grant.NodeType,
		Tags:        core.StringList(req.Tags),
		Endpoints:   core.StringList(req.Endpoints),
		IsActive:    true,
		LastSeenAt:  time.Now(),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	delegationRes, err := s.delegator.Delegate(ctx, nodeID)
	if err == nil && delegationRes != nil {
		node.AssignedPoPID = &delegationRes.PrimaryPoP.ID
		node.AssignedPoP = &delegationRes.PrimaryPoP
	}

	if err := s.db.Nodes.Create(ctx, node); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to save node: %v", err)
	}

	// Fetch peers
	existingNodes, _ := s.db.Nodes.ListByNetworkID(ctx, network.ID)
	var protoPeers []*v1.Node
	for _, n := range existingNodes {
		if n.PublicKey != req.PublicKey {
			protoPeers = append(protoPeers, &v1.Node{
				Id:          n.ID.String(),
				Hostname:    n.Hostname,
				PublicKey:   n.PublicKey,
				OverlayIpv4: n.OverlayIPv4,
				OverlayIpv6: n.OverlayIPv6,
				NodeType:    string(n.NodeType),
				Tags:        []string(n.Tags),
				Endpoints:   []string(n.Endpoints),
			})
		}
	}

	var protoPrimary, protoSecondary *v1.EdgePoP
	if delegationRes != nil {
		protoPrimary = &v1.EdgePoP{
			Id:             delegationRes.PrimaryPoP.ID.String(),
			PopCode:        delegationRes.PrimaryPoP.PoPCode,
			Region:         delegationRes.PrimaryPoP.Region,
			PublicEndpoint: delegationRes.PrimaryPoP.PublicEndpoint,
			PublicKey:      delegationRes.PrimaryPoP.PublicKey,
			IsAnycast:      delegationRes.PrimaryPoP.IsAnycast,
			Weight:         int32(delegationRes.PrimaryPoP.Weight),
		}
		if delegationRes.SecondaryPoP != nil {
			protoSecondary = &v1.EdgePoP{
				Id:             delegationRes.SecondaryPoP.ID.String(),
				PopCode:        delegationRes.SecondaryPoP.PoPCode,
				Region:         delegationRes.SecondaryPoP.Region,
				PublicEndpoint: delegationRes.SecondaryPoP.PublicEndpoint,
				PublicKey:      delegationRes.SecondaryPoP.PublicKey,
				IsAnycast:      delegationRes.SecondaryPoP.IsAnycast,
				Weight:         int32(delegationRes.SecondaryPoP.Weight),
			}
		}
	}

	s.bus.Publish(events.Scope{TenantID: network.TenantID, NetworkID: network.ID}, "node_enrolled", map[string]any{
		"node_id":      node.ID.String(),
		"hostname":     node.Hostname,
		"overlay_ipv4": node.OverlayIPv4,
		"node_type":    string(node.NodeType),
	})

	return &v1.EnrollResponse{
		NodeId:       node.ID.String(),
		NetworkId:    network.ID,
		OverlayIpv4:  node.OverlayIPv4,
		OverlayIpv6:  node.OverlayIPv6,
		DnsDomain:    network.DNSDomain,
		Mtu:          int32(network.MTU),
		PrimaryPop:   protoPrimary,
		SecondaryPop: protoSecondary,
		Peers:        protoPeers,
	}, nil
}

// ReportProbes records smart routing telemetry over gRPC.
func (s *Server) ReportProbes(ctx context.Context, req *v1.ProbeReportRequest) (*v1.ProbeReportResponse, error) {
	nodeUUID, err := uuid.Parse(req.NodeId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid node_id: %v", err)
	}

	sample := core.LatencySample{
		NodeID:     nodeUUID,
		PoPCode:    req.PopCode,
		RTT:        time.Duration(req.RttNs),
		PacketLoss: req.PacketLoss,
		Timestamp:  time.Now(),
	}

	s.delegator.RecordProbe(sample)
	delegationRes, _ := s.delegator.Delegate(ctx, nodeUUID)

	code := ""
	if delegationRes != nil {
		code = delegationRes.PrimaryPoP.PoPCode
	}

	return &v1.ProbeReportResponse{
		Accepted:       true,
		PrimaryPopCode: code,
	}, nil
}

// DiscoverP2P returns coordinates for direct P2P WireGuard hole punching.
func (s *Server) DiscoverP2P(ctx context.Context, req *v1.P2PDiscoverRequest) (*v1.P2PDiscoverResponse, error) {
	initiatorUUID, err := uuid.Parse(req.InitiatorNodeId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid initiator_node_id: %v", err)
	}

	initiator, err := s.db.Nodes.GetByID(ctx, initiatorUUID)
	if err != nil || initiator == nil {
		return nil, status.Errorf(codes.NotFound, "initiator node not found: %v", err)
	}

	target, err := s.db.Nodes.GetByOverlayIP(ctx, initiator.NetworkID, req.TargetOverlayIp)
	if err != nil || target == nil {
		return nil, status.Errorf(codes.NotFound, "target overlay IP %s not found", req.TargetOverlayIp)
	}

	var protoPrimary *v1.EdgePoP
	if target.AssignedPoP != nil {
		protoPrimary = &v1.EdgePoP{
			Id:             target.AssignedPoP.ID.String(),
			PopCode:        target.AssignedPoP.PoPCode,
			Region:         target.AssignedPoP.Region,
			PublicEndpoint: target.AssignedPoP.PublicEndpoint,
			PublicKey:      target.AssignedPoP.PublicKey,
			IsAnycast:      target.AssignedPoP.IsAnycast,
		}
	}

	return &v1.P2PDiscoverResponse{
		TargetNodeId:      target.ID.String(),
		TargetHostname:    target.Hostname,
		TargetPublicKey:   target.PublicKey,
		TargetOverlayIpv4: target.OverlayIPv4,
		TargetEndpoints:   []string(target.Endpoints),
		PrimaryPop:        protoPrimary,
	}, nil
}

// SyncEdgeMesh synchronizes global PoPs and Nodes with Edge Data Plane PoPs.
func (s *Server) SyncEdgeMesh(ctx context.Context, req *v1.EdgeSyncRequest) (*v1.EdgeSyncResponse, error) {
	pops, err := s.db.EdgePoPs.ListHealthy(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list pops: %v", err)
	}

	var allNodes []core.Node
	tenants, _ := s.db.Tenants.List(ctx)
	for _, t := range tenants {
		nets, _ := s.db.Networks.ListByTenantID(ctx, t.ID)
		for _, n := range nets {
			nodes, _ := s.db.Nodes.ListByNetworkID(ctx, n.ID)
			allNodes = append(allNodes, nodes...)
		}
	}

	var protoPoPs []*v1.EdgePoP
	for _, p := range pops {
		protoPoPs = append(protoPoPs, &v1.EdgePoP{
			Id:             p.ID.String(),
			PopCode:        p.PoPCode,
			Region:         p.Region,
			PublicEndpoint: p.PublicEndpoint,
			PublicKey:      p.PublicKey,
			IsAnycast:      p.IsAnycast,
			Weight:         int32(p.Weight),
		})
	}

	var protoNodes []*v1.Node
	for _, n := range allNodes {
		protoNodes = append(protoNodes, &v1.Node{
			Id:          n.ID.String(),
			Hostname:    n.Hostname,
			PublicKey:   n.PublicKey,
			OverlayIpv4: n.OverlayIPv4,
			OverlayIpv6: n.OverlayIPv6,
			NodeType:    string(n.NodeType),
			Tags:        []string(n.Tags),
			Endpoints:   []string(n.Endpoints),
		})
	}

	return &v1.EdgeSyncResponse{
		Pops:  protoPoPs,
		Nodes: protoNodes,
	}, nil
}

// GetGatewayRoutes builds and returns dynamic backend pools for Ingress Gateways.
func (s *Server) GetGatewayRoutes(ctx context.Context, req *v1.GatewayRoutesRequest) (*v1.GatewayRoutesResponse, error) {
	tunnels, err := s.db.Tunnels.ListAll(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list tunnels: %v", err)
	}

	routesMap := make(map[string]*v1.GatewayRoute)

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
			route = &v1.GatewayRoute{
				Hostname: t.PublicHostname,
				Protocol: proto,
				Backends: make([]*v1.GatewayBackend, 0, 2),
			}
			routesMap[t.PublicHostname] = route
		}

		route.Backends = append(route.Backends, &v1.GatewayBackend{
			Address:      targetAddr,
			NodeId:       node.ID.String(),
			NodeHostname: node.Hostname,
			Weight:       100,
			Healthy:      true,
		})
	}

	var protoRoutes []*v1.GatewayRoute
	for _, r := range routesMap {
		protoRoutes = append(protoRoutes, r)
	}

	return &v1.GatewayRoutesResponse{
		Routes: protoRoutes,
	}, nil
}

// StreamMeshEvents provides a persistent real-time event bus over gRPC streaming.
func (s *Server) StreamMeshEvents(req *v1.StreamEventsRequest, stream v1.ControlPlaneService_StreamMeshEventsServer) error {
	scope, err := s.streamScope(stream.Context())
	if err != nil {
		return err
	}
	sub := s.bus.Subscribe(scope)
	defer sub.Close()

	slog.Info("gRPC client connected to real-time event stream", "subscriber", req.SubscriberId, "role", req.Role)

	if err := stream.Send(&v1.MeshEvent{
		EventType:   "connected",
		Timestamp:   time.Now().UnixNano(),
		PayloadJson: fmt.Sprintf(`{"status":"connected","role":%q}`, req.Role),
	}); err != nil {
		return err
	}

	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case msg, ok := <-sub.C:
			if !ok {
				return status.Error(codes.ResourceExhausted, "event stream too slow; reconnect and resync")
			}
			if err := stream.Send(&v1.MeshEvent{
				EventType:   msg.Event,
				Timestamp:   msg.Timestamp.UnixNano(),
				PayloadJson: string(msg.Data),
			}); err != nil {
				return err
			}
		}
	}
}

// BroadcastEvent publishes an unscoped (control-plane wide) event.
func (s *Server) BroadcastEvent(eventType string, payload any) {
	s.bus.Publish(events.Scope{}, eventType, payload)
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
