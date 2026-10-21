package grpc

import (
	"context"

	controlauth "github.com/cubis/zro/pkg/control/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Authenticator resolves the caller's credentials (gRPC metadata) into a
// context carrying a controlauth.Subject.
type Authenticator func(ctx context.Context) (context.Context, error)

// access is the principal kind an RPC requires.
type access int

const (
	accessPublic access = iota // no credentials (the call carries its own proof)
	accessNode
	accessEdge
	accessAny // any authenticated principal; the handler scopes what it returns
)

// policy lists every RPC. A method missing from it is denied, so adding an RPC
// without deciding who may call it fails closed.
var policy = map[string]access{
	"/zro.control.v1.ControlPlaneService/Enroll":           accessPublic,
	"/zro.control.v1.ControlPlaneService/ReportProbes":     accessNode,
	"/zro.control.v1.ControlPlaneService/DiscoverP2P":      accessNode,
	"/zro.control.v1.ControlPlaneService/GetGatewayRoutes": accessNode,
	"/zro.control.v1.ControlPlaneService/Deregister":       accessNode,
	"/zro.control.v1.ControlPlaneService/RegisterTunnel":   accessNode,
	"/zro.control.v1.ControlPlaneService/ListTunnels":      accessNode,
	"/zro.control.v1.ControlPlaneService/DeleteTunnel":     accessNode,
	"/zro.control.v1.ControlPlaneService/SyncEdgeMesh":     accessEdge,
	"/zro.control.v1.ControlPlaneService/StreamMeshEvents": accessAny,
}

// authorize authenticates the call and checks the principal against the policy.
func (s *Server) authorize(ctx context.Context, method string) (context.Context, error) {
	need, known := policy[method]
	if !known {
		return ctx, status.Error(codes.PermissionDenied, "method not permitted")
	}
	if need == accessPublic {
		return ctx, nil
	}
	ctx, err := s.authn(ctx)
	if err != nil {
		return ctx, err
	}
	subject := controlauth.FromContext(ctx)
	switch {
	case subject == nil:
		return ctx, status.Error(codes.Unauthenticated, "credentials required")
	case need == accessNode && subject.Kind != controlauth.KindNode:
		return ctx, status.Error(codes.PermissionDenied, "a node token is required")
	case need == accessEdge && (subject.Kind != controlauth.KindEdge || subject.PoPCode == ""):
		return ctx, status.Error(codes.PermissionDenied, "a per-PoP edge credential is required")
	}
	if n := subject.Node; n != nil {
		s.svc.Touch(ctx, n)
	}
	return ctx, nil
}

// UnaryInterceptor enforces the method policy on unary RPCs.
func (s *Server) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		ctx, err := s.authorize(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return h(ctx, req)
	}
}

// StreamInterceptor enforces the method policy on streaming RPCs.
func (s *Server) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
		ctx, err := s.authorize(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return h(srv, &authedStream{ServerStream: ss, ctx: ctx})
	}
}

type authedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (a *authedStream) Context() context.Context { return a.ctx }
