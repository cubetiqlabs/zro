package grpc

import (
	"context"
	"fmt"
	"io"

	v1 "github.com/cubis/zro/api/proto/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client provides a type-safe client for the Control Plane gRPC service.
type Client struct {
	conn   *grpc.ClientConn
	client v1.ControlPlaneServiceClient
}

// NewClient initializes a connection to the Control Plane gRPC server.
func NewClient(target string, opts ...grpc.DialOption) (*Client, error) {
	if len(opts) == 0 {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	return &Client{
		conn:   conn,
		client: v1.NewControlPlaneServiceClient(conn),
	}, nil
}

// Close releases the gRPC connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// RawClient returns the underlying generated protobuf client.
func (c *Client) RawClient() v1.ControlPlaneServiceClient {
	return c.client
}

// Enroll performs authenticated node or gateway registration over gRPC.
func (c *Client) Enroll(ctx context.Context, req *v1.EnrollRequest) (*v1.EnrollResponse, error) {
	return c.client.Enroll(ctx, req)
}

// ReportProbes submits real-time latency probe telemetry over gRPC.
func (c *Client) ReportProbes(ctx context.Context, req *v1.ProbeReportRequest) (*v1.ProbeReportResponse, error) {
	return c.client.ReportProbes(ctx, req)
}

// DiscoverP2P requests coordinates for direct P2P hole punching over gRPC.
func (c *Client) DiscoverP2P(ctx context.Context, req *v1.P2PDiscoverRequest) (*v1.P2PDiscoverResponse, error) {
	return c.client.DiscoverP2P(ctx, req)
}

// SyncEdgeMesh synchronizes global mesh topology over gRPC.
func (c *Client) SyncEdgeMesh(ctx context.Context, req *v1.EdgeSyncRequest) (*v1.EdgeSyncResponse, error) {
	return c.client.SyncEdgeMesh(ctx, req)
}

// GetGatewayRoutes retrieves dynamic backend routes for Ingress Gateways over gRPC.
func (c *Client) GetGatewayRoutes(ctx context.Context, req *v1.GatewayRoutesRequest) (*v1.GatewayRoutesResponse, error) {
	return c.client.GetGatewayRoutes(ctx, req)
}

// StreamEvents listens to real-time mesh events over a persistent gRPC stream.
func (c *Client) StreamEvents(ctx context.Context, role, subscriberID string, onEvent func(*v1.MeshEvent)) error {
	stream, err := c.client.StreamMeshEvents(ctx, &v1.StreamEventsRequest{
		Role:         role,
		SubscriberId: subscriberID,
	})
	if err != nil {
		return fmt.Errorf("failed to open gRPC event stream: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			evt, err := stream.Recv()
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return fmt.Errorf("error receiving from gRPC event stream: %w", err)
			}
			if onEvent != nil {
				onEvent(evt)
			}
		}
	}
}
