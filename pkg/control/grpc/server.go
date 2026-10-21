package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	v1 "github.com/cubis/zro/api/proto/v1"
	"github.com/cubis/zro/pkg/config"
	controlauth "github.com/cubis/zro/pkg/control/auth"
	"github.com/cubis/zro/pkg/control/events"
	"github.com/cubis/zro/pkg/control/service"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/store"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements the ControlPlaneServiceServer for gRPC. It is a thin
// adapter over service.Service, so REST and gRPC enforce identical rules.
type Server struct {
	v1.UnimplementedControlPlaneServiceServer
	cfg *config.ControlPlaneConfig
	db  *store.DB
	svc *service.Service

	bus         *events.Bus
	streamScope func(context.Context) (events.Scope, error)
	authn       Authenticator
}

// NewServer creates a new gRPC Control Plane Server.
func NewServer(cfg *config.ControlPlaneConfig, db *store.DB, svc *service.Service) *Server {
	return &Server{
		cfg: cfg,
		db:  db,
		svc: svc,
		bus: events.NewBus(),
		streamScope: func(context.Context) (events.Scope, error) {
			return events.Scope{}, status.Error(codes.Unauthenticated, "event streams are not configured")
		},
		authn: func(ctx context.Context) (context.Context, error) {
			return ctx, status.Error(codes.Unauthenticated, "authentication is not configured")
		},
	}
}

// SetEventSource wires the shared event bus and the function that decides
// which events an incoming stream may see. Streams fail closed until set.
func (s *Server) SetEventSource(bus *events.Bus, scope func(context.Context) (events.Scope, error)) {
	s.bus, s.streamScope = bus, scope
}

// SetAuthenticator installs the credential check used by the interceptors.
// RPCs other than Enroll fail closed until it is set.
func (s *Server) SetAuthenticator(a Authenticator) { s.authn = a }

// node returns the authenticated node of an RPC context.
func node(ctx context.Context) *core.Node { return controlauth.NodeFromContext(ctx) }

// toStatus maps a service error to a gRPC status.
func toStatus(err error) error {
	if err == nil {
		return nil
	}
	code := codes.Internal
	switch service.KindOf(err) {
	case service.KindInvalid:
		code = codes.InvalidArgument
	case service.KindUnauthenticated:
		code = codes.Unauthenticated
	case service.KindForbidden:
		code = codes.PermissionDenied
	case service.KindNotFound:
		code = codes.NotFound
	case service.KindConflict:
		code = codes.AlreadyExists
	case service.KindExhausted:
		code = codes.ResourceExhausted
	}
	if code == codes.Internal {
		slog.Error("gRPC request failed", "error", err)
	}
	return status.Error(code, service.Message(err))
}

func toProtoPoP(p *core.EdgePoP) *v1.EdgePoP {
	if p == nil || p.ID == uuid.Nil {
		return nil
	}
	return &v1.EdgePoP{
		Id:             p.ID.String(),
		PopCode:        p.PoPCode,
		Region:         p.Region,
		PublicEndpoint: p.PublicEndpoint,
		PublicKey:      p.PublicKey,
		IsAnycast:      p.IsAnycast,
		Weight:         int32(p.Weight),
	}
}

func toProtoNode(n *core.Node) *v1.Node {
	popCode := ""
	if n.AssignedPoP != nil {
		popCode = n.AssignedPoP.PoPCode
	}
	return &v1.Node{
		AssignedPopCode: popCode,
		Id:              n.ID.String(),
		Hostname:        n.Hostname,
		PublicKey:       n.PublicKey,
		OverlayIpv4:     n.OverlayIPv4,
		OverlayIpv6:     n.OverlayIPv6,
		NodeType:        string(n.NodeType),
		Tags:            []string(n.Tags),
		AllowedIps:      []string(n.AllowedIPs),
		Endpoints:       []string(n.Endpoints),
	}
}

func toProtoRules(rules []core.ACLRule) []*v1.ACLRule {
	out := make([]*v1.ACLRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, &v1.ACLRule{
			Id: r.ID.String(), Priority: int32(r.Priority), SourceIp: r.SourceIP, DestIp: r.DestIP,
			SourceTag: r.SourceTag, DestTag: r.DestTag, Protocol: r.Protocol, Ports: r.Ports, Action: string(r.Action),
		})
	}
	return out
}

func toProtoTunnel(t *core.Tunnel) *v1.Tunnel {
	return &v1.Tunnel{
		Id:             t.ID.String(),
		Name:           t.Name,
		LocalAddress:   t.LocalAddress,
		PublicHostname: t.PublicHostname,
		Protocol:       t.Protocol,
	}
}

// Enroll handles cryptographic node and gateway enrollment over gRPC.
func (s *Server) Enroll(ctx context.Context, req *v1.EnrollRequest) (*v1.EnrollResponse, error) {
	probes := make([]core.LatencySample, 0, len(req.Probes))
	for _, p := range req.Probes {
		probes = append(probes, core.LatencySample{PoPCode: p.PopCode, RTT: time.Duration(p.RttNs), PacketLoss: p.PacketLoss})
	}
	resp, err := s.svc.Enroll(ctx, service.EnrollRequest{
		Token:        req.Token,
		PublicKey:    req.PublicKey,
		Hostname:     req.Hostname,
		NodeType:     core.NodeType(req.NodeType),
		Tags:         req.Tags,
		Endpoints:    req.Endpoints,
		AllowedPorts: req.AllowedPorts,
		DefaultDeny:  req.DefaultDeny,
		Probes:       probes,
	})
	if err != nil {
		return nil, toStatus(err)
	}

	out := &v1.EnrollResponse{
		NodeId:       resp.NodeID.String(),
		NetworkId:    resp.NetworkID,
		NodeToken:    resp.NodeToken,
		OverlayIpv4:  resp.OverlayIPv4,
		OverlayIpv6:  resp.OverlayIPv6,
		DnsDomain:    resp.DNSDomain,
		Mtu:          int32(resp.MTU),
		Ipv4Cidr:     resp.IPv4CIDR,
		Ipv6Cidr:     resp.IPv6CIDR,
		AllowedIps:   resp.AllowedIPs,
		AllowedPorts: resp.AllowedPorts,
		DefaultDeny:  resp.DefaultDeny,
		AclRules:     toProtoRules(resp.ACLRules),
		PrimaryPop:   toProtoPoP(&resp.PrimaryPoP),
		SecondaryPop: toProtoPoP(resp.SecondaryPoP),
	}
	for i := range resp.Peers {
		if resp.Peers[i].ID != resp.NodeID {
			out.Peers = append(out.Peers, toProtoNode(&resp.Peers[i]))
		}
	}
	return out, nil
}

// ReportProbes records smart routing telemetry over gRPC.
func (s *Server) ReportProbes(ctx context.Context, req *v1.ProbeReportRequest) (*v1.ProbeReportResponse, error) {
	primary := s.svc.ReportProbe(ctx, node(ctx), core.LatencySample{
		PoPCode:    req.PopCode,
		RTT:        time.Duration(req.RttNs),
		PacketLoss: req.PacketLoss,
	})
	return &v1.ProbeReportResponse{Accepted: true, PrimaryPopCode: primary}, nil
}

// DiscoverP2P returns coordinates for direct P2P WireGuard hole punching.
func (s *Server) DiscoverP2P(ctx context.Context, req *v1.P2PDiscoverRequest) (*v1.P2PDiscoverResponse, error) {
	var initiator uuid.UUID
	if req.InitiatorNodeId != "" {
		var err error
		if initiator, err = uuid.Parse(req.InitiatorNodeId); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid initiator_node_id: %v", err)
		}
	}
	resp, err := s.svc.DiscoverP2P(ctx, node(ctx), service.P2PDiscoverRequest{
		InitiatorNodeID:    initiator,
		TargetOverlayIP:    req.TargetOverlayIp,
		InitiatorEndpoints: req.InitiatorEndpoints,
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &v1.P2PDiscoverResponse{
		TargetNodeId:      resp.TargetNodeID.String(),
		TargetHostname:    resp.TargetHostname,
		TargetPublicKey:   resp.TargetPublicKey,
		TargetOverlayIpv4: resp.TargetOverlayIPv4,
		TargetOverlayIpv6: resp.TargetOverlayIPv6,
		TargetEndpoints:   resp.TargetEndpoints,
		PrimaryPop:        toProtoPoP(resp.PrimaryPoP),
		SecondaryPop:      toProtoPoP(resp.SecondaryPoP),
	}, nil
}

// SyncEdgeMesh synchronizes global PoPs and Nodes with Edge Data Plane PoPs.
func (s *Server) SyncEdgeMesh(ctx context.Context, _ *v1.EdgeSyncRequest) (*v1.EdgeSyncResponse, error) {
	snap, err := s.svc.EdgeSync(ctx)
	if err != nil {
		return nil, toStatus(err)
	}
	out := &v1.EdgeSyncResponse{Prefixes: snap.Prefixes}
	for i := range snap.PoPs {
		out.Pops = append(out.Pops, toProtoPoP(&snap.PoPs[i]))
	}
	for i := range snap.Nodes {
		out.Nodes = append(out.Nodes, toProtoNode(&snap.Nodes[i]))
	}
	return out, nil
}

// GetGatewayRoutes returns the dynamic backend pools of the caller's network.
func (s *Server) GetGatewayRoutes(ctx context.Context, _ *v1.GatewayRoutesRequest) (*v1.GatewayRoutesResponse, error) {
	routes, err := s.svc.GatewayRoutes(ctx, node(ctx).NetworkID)
	if err != nil {
		return nil, toStatus(err)
	}
	out := &v1.GatewayRoutesResponse{}
	for _, r := range routes {
		route := &v1.GatewayRoute{Hostname: r.Hostname, Protocol: r.Protocol}
		for _, b := range r.Backends {
			route.Backends = append(route.Backends, &v1.GatewayBackend{
				Address:      b.Address,
				NodeId:       b.NodeID.String(),
				NodeHostname: b.NodeHostname,
				Weight:       int32(b.Weight),
				Healthy:      b.Healthy,
			})
		}
		out.Routes = append(out.Routes, route)
	}
	return out, nil
}

// GetACLPolicy returns the network-wide access rules the node must enforce.
func (s *Server) GetACLPolicy(ctx context.Context, _ *v1.GetACLPolicyRequest) (*v1.GetACLPolicyResponse, error) {
	rules, err := s.svc.ACLPolicy(ctx, node(ctx))
	if err != nil {
		return nil, toStatus(err)
	}
	return &v1.GetACLPolicyResponse{Rules: toProtoRules(rules)}, nil
}

// ListPeers returns the members of the caller's network.
func (s *Server) ListPeers(ctx context.Context, _ *v1.ListPeersRequest) (*v1.ListPeersResponse, error) {
	peers, err := s.svc.Peers(ctx, node(ctx))
	if err != nil {
		return nil, toStatus(err)
	}
	out := &v1.ListPeersResponse{}
	for i := range peers {
		out.Peers = append(out.Peers, toProtoNode(&peers[i]))
	}
	return out, nil
}

// Deregister removes the calling node from the mesh.
func (s *Server) Deregister(ctx context.Context, _ *v1.DeregisterRequest) (*v1.DeregisterResponse, error) {
	if err := s.svc.Deregister(ctx, node(ctx)); err != nil {
		return nil, toStatus(err)
	}
	return &v1.DeregisterResponse{}, nil
}

// RegisterTunnel exposes a local service of the calling node.
func (s *Server) RegisterTunnel(ctx context.Context, req *v1.RegisterTunnelRequest) (*v1.Tunnel, error) {
	t, err := s.svc.RegisterTunnel(ctx, node(ctx), core.Tunnel{
		Name: req.Name, LocalAddress: req.LocalAddress, PublicHostname: req.PublicHostname, Protocol: req.Protocol,
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return toProtoTunnel(t), nil
}

// ListTunnels returns the tunnels of the caller's network.
func (s *Server) ListTunnels(ctx context.Context, _ *v1.ListTunnelsRequest) (*v1.ListTunnelsResponse, error) {
	tunnels, err := s.svc.ListTunnels(ctx, node(ctx))
	if err != nil {
		return nil, toStatus(err)
	}
	out := &v1.ListTunnelsResponse{}
	for i := range tunnels {
		out.Tunnels = append(out.Tunnels, toProtoTunnel(&tunnels[i]))
	}
	return out, nil
}

// DeleteTunnel removes a tunnel owned by the calling node.
func (s *Server) DeleteTunnel(ctx context.Context, req *v1.DeleteTunnelRequest) (*v1.DeleteTunnelResponse, error) {
	id, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid tunnel id: %v", err)
	}
	if err := s.svc.DeleteTunnel(ctx, node(ctx), id); err != nil {
		return nil, toStatus(err)
	}
	return &v1.DeleteTunnelResponse{}, nil
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
