package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	v1 "github.com/cubis/zro/api/proto/v1"
	"github.com/cubis/zro/pkg/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Client provides a type-safe client for the Control Plane gRPC service.
type Client struct {
	conn   *grpc.ClientConn
	client v1.ControlPlaneServiceClient
}

// DialOptions configures a Control Plane connection.
type DialOptions struct {
	// Endpoint is the gRPC address ("host:port"); an http(s):// prefix is ignored.
	Endpoint string
	// Insecure disables TLS. Tokens then travel in clear text, so it must be an
	// explicit operator choice (for example behind a TLS-terminating proxy).
	Insecure bool
	// CAFile optionally pins the CA that signed the plane's certificate.
	CAFile string
	// Token supplies the bearer credential (node token or edge key) attached to
	// every RPC; it is read per call so it can change after enrollment.
	Token func() string
}

// Dial connects to the Control Plane, using TLS unless opts.Insecure is set.
func Dial(opts DialOptions) (*Client, error) {
	target := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(opts.Endpoint), "https://"), "http://")
	if target == "" {
		return nil, errors.New("gRPC endpoint is empty")
	}

	var creds credentials.TransportCredentials
	if opts.Insecure {
		creds = insecure.NewCredentials()
	} else {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if opts.CAFile != "" {
			pem, err := os.ReadFile(opts.CAFile)
			if err != nil {
				return nil, fmt.Errorf("reading plane CA file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("plane CA file contains no valid certificates")
			}
			tlsCfg.RootCAs = pool
		}
		creds = credentials.NewTLS(tlsCfg)
	}

	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	if opts.Token != nil {
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(tokenCreds{token: opts.Token, secure: !opts.Insecure}))
	}
	return NewClient(target, dialOpts...)
}

// tokenCreds attaches a bearer token to each RPC.
type tokenCreds struct {
	token  func() string
	secure bool
}

func (t tokenCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	if tok := t.token(); tok != "" {
		return map[string]string{"authorization": "Bearer " + tok}, nil
	}
	return nil, nil
}

// RequireTransportSecurity makes gRPC refuse to send the token over plaintext
// unless the operator chose Insecure.
func (t tokenCreds) RequireTransportSecurity() bool { return t.secure }

// NewClient initializes a connection with explicit dial options. Prefer Dial.
func NewClient(target string, opts ...grpc.DialOption) (*Client, error) {
	if len(opts) == 0 {
		return nil, errors.New("gRPC dial options (transport credentials) are required")
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

// RegisterTunnel exposes a local service of the calling node.
func (c *Client) RegisterTunnel(ctx context.Context, req *v1.RegisterTunnelRequest) (*v1.Tunnel, error) {
	return c.client.RegisterTunnel(ctx, req)
}

// ListTunnels lists the tunnels of the caller's network.
func (c *Client) ListTunnels(ctx context.Context) (*v1.ListTunnelsResponse, error) {
	return c.client.ListTunnels(ctx, &v1.ListTunnelsRequest{})
}

// DeleteTunnel removes a tunnel owned by the calling node.
func (c *Client) DeleteTunnel(ctx context.Context, id string) error {
	_, err := c.client.DeleteTunnel(ctx, &v1.DeleteTunnelRequest{Id: id})
	return err
}

// DialPlane connects an agent to the plane using its PlaneGRPC settings. The
// gRPC endpoint falls back to the REST endpoint's host:port when unset.
func DialPlane(planeEndpoint string, g config.PlaneGRPC, token func() string) (*Client, error) {
	endpoint := g.GRPCEndpoint
	if endpoint == "" {
		endpoint = planeEndpoint
	}
	return Dial(DialOptions{Endpoint: endpoint, Insecure: g.GRPCInsecure, CAFile: g.CAFile, Token: token})
}

// Deregister removes the calling node from the mesh.
func (c *Client) Deregister(ctx context.Context) error {
	_, err := c.client.Deregister(ctx, &v1.DeregisterRequest{})
	return err
}

// ListPeers lists the members of the caller's network.
func (c *Client) ListPeers(ctx context.Context) (*v1.ListPeersResponse, error) {
	return c.client.ListPeers(ctx, &v1.ListPeersRequest{})
}
