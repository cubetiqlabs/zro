package grpc

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/cubetiqlabs/zro/api/proto/v1"
	"github.com/cubetiqlabs/zro/pkg/config"
	controlauth "github.com/cubetiqlabs/zro/pkg/control/auth"
	"github.com/cubetiqlabs/zro/pkg/control/events"
	"github.com/cubetiqlabs/zro/pkg/control/service"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/cubetiqlabs/zro/pkg/crypto"
	"github.com/cubetiqlabs/zro/pkg/store"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestGRPCControlPlaneService(t *testing.T) {
	ctx := context.Background()

	// 1. Initialize SQLite Store
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}

	secretKey := "test-grpc-cluster-secret-key-32b"
	cfg := &config.ControlPlaneConfig{
		SecretKey:     secretKey,
		DefaultCIDRv4: "100.64.0.0/10",
		DefaultCIDRv6: "fd00:cafe::/64",
	}

	tenant := core.Tenant{
		ID:       uuid.New(),
		Name:     "Test Org",
		Slug:     "test-org",
		APIKey:   "test-api-key",
		IsActive: true,
	}
	_ = db.Tenants.Create(ctx, &tenant)

	// Create test network
	networkID := core.GenerateNetworkID()
	netObj := core.Network{
		ID:        networkID,
		TenantID:  tenant.ID,
		Name:      "gRPC Test Network",
		IPv4CIDR:  "100.64.0.0/10",
		IPv6CIDR:  "fd00:cafe::/64",
		DNSDomain: "zro.internal",
		MTU:       1420,
		IsActive:  true,
	}
	if err := db.Networks.Create(ctx, &netObj); err != nil {
		t.Fatalf("failed to create network: %v", err)
	}

	// 2. Start gRPC Server
	bus := events.NewBus()
	ctrlServer := NewServer(cfg, db, service.New(cfg, db, bus))
	ctrlServer.SetEventSource(bus, testScope)
	ctrlServer.SetAuthenticator(testAuthenticator(db, "edge-secret"))
	grpcSrv := grpc.NewServer(
		grpc.UnaryInterceptor(ctrlServer.UnaryInterceptor()),
		grpc.StreamInterceptor(ctrlServer.StreamInterceptor()),
	)
	v1.RegisterControlPlaneServiceServer(grpcSrv, ctrlServer)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on TCP: %v", err)
	}
	defer lis.Close()

	go func() {
		_ = grpcSrv.Serve(lis)
	}()
	defer grpcSrv.GracefulStop()

	// 3. Connect gRPC Client
	client, err := NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	dial := func(token string) *Client {
		c, err := Dial(DialOptions{Endpoint: lis.Addr().String(), Insecure: true, Token: func() string { return token }})
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	edgeClient := dial("edge-secret")

	// 4. Test Real-time Streaming Events
	var receivedEvents []*v1.MeshEvent
	var evMu sync.Mutex
	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()

	go func() {
		_ = edgeClient.StreamEvents(streamCtx, "edge", "pop1", func(evt *v1.MeshEvent) {
			evMu.Lock()
			receivedEvents = append(receivedEvents, evt)
			evMu.Unlock()
		})
	}()

	time.Sleep(50 * time.Millisecond) // Allow stream to connect

	// 5. Test gRPC Enroll Node 1
	kp1, _ := crypto.GenerateKeyPair()
	token1 := crypto.GenerateEnrollmentToken(secretKey, networkID, "test-grpc-node-1", 1*time.Hour, kp1.PublicKey)

	enroll1Resp, err := client.Enroll(ctx, &v1.EnrollRequest{
		Token:     token1,
		PublicKey: kp1.PublicKey,
		Hostname:  "test-grpc-node-1",
		NodeType:  "peer",
		Tags:      []string{"tag:grpc"},
		Endpoints: []string{"192.168.1.50:51820"},
	})
	if err != nil {
		t.Fatalf("gRPC Enroll failed: %v", err)
	}

	if enroll1Resp.OverlayIpv4 != "100.64.0.2" {
		t.Fatalf("expected overlay IP 100.64.0.2, got %s", enroll1Resp.OverlayIpv4)
	}
	t.Logf("✅ gRPC Enroll node 1 verified: allocated overlay IP %s", enroll1Resp.OverlayIpv4)

	// Enroll Node 2
	kp2, _ := crypto.GenerateKeyPair()
	token2 := crypto.GenerateEnrollmentToken(secretKey, networkID, "test-grpc-node-2", 1*time.Hour, kp2.PublicKey)

	enroll2Resp, err := client.Enroll(ctx, &v1.EnrollRequest{
		Token:     token2,
		PublicKey: kp2.PublicKey,
		Hostname:  "test-grpc-node-2",
		NodeType:  "peer",
		Tags:      []string{"tag:grpc"},
		Endpoints: []string{"192.168.1.51:51820"},
	})
	if err != nil {
		t.Fatalf("gRPC Enroll node 2 failed: %v", err)
	}

	node1Client := dial(enroll1Resp.NodeToken)
	if enroll1Resp.NodeToken == "" {
		t.Fatal("gRPC Enroll must return a node token")
	}

	// Access policy: anonymous callers and wrong principals are refused.
	if _, err := client.ReportProbes(ctx, &v1.ProbeReportRequest{PopCode: "KH"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("anonymous ReportProbes: expected Unauthenticated, got %v", err)
	}
	if _, err := node1Client.SyncEdgeMesh(ctx, &v1.EdgeSyncRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("node calling SyncEdgeMesh: expected PermissionDenied, got %v", err)
	}
	if _, err := edgeClient.ReportProbes(ctx, &v1.ProbeReportRequest{PopCode: "KH"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("edge calling ReportProbes: expected PermissionDenied, got %v", err)
	}
	kpX, _ := crypto.GenerateKeyPair()
	if _, err := client.Enroll(ctx, &v1.EnrollRequest{Token: token1, PublicKey: kpX.PublicKey}); status.Code(err) == codes.OK {
		t.Fatal("enrollment token bound to another key must be rejected")
	}

	// 6. Test gRPC ReportProbes
	probeResp, err := node1Client.ReportProbes(ctx, &v1.ProbeReportRequest{
		NodeId:     enroll1Resp.NodeId,
		PopCode:    "KH",
		RttNs:      5000000,
		PacketLoss: 0.0,
	})
	if err != nil || !probeResp.Accepted {
		t.Fatalf("gRPC ReportProbes failed: %v", err)
	}
	t.Log("✅ gRPC ReportProbes telemetry intake verified")

	// 7. Test gRPC DiscoverP2P
	discResp, err := node1Client.DiscoverP2P(ctx, &v1.P2PDiscoverRequest{
		InitiatorNodeId: enroll1Resp.NodeId,
		TargetOverlayIp: enroll2Resp.OverlayIpv4,
	})
	if err != nil {
		t.Fatalf("gRPC DiscoverP2P failed: %v", err)
	}
	if discResp.TargetPublicKey != kp2.PublicKey {
		t.Fatalf("gRPC DiscoverP2P target mismatch, got %s", discResp.TargetPublicKey)
	}
	t.Log("✅ gRPC DiscoverP2P coordinates verified")

	// 8. Test gRPC SyncEdgeMesh
	syncResp, err := edgeClient.SyncEdgeMesh(ctx, &v1.EdgeSyncRequest{PopCode: "KH"})
	if err != nil {
		t.Fatalf("gRPC SyncEdgeMesh failed: %v", err)
	}
	if len(syncResp.Nodes) != 2 {
		t.Fatalf("expected 2 active nodes in mesh sync, got %d", len(syncResp.Nodes))
	}
	t.Logf("✅ gRPC SyncEdgeMesh verified (%d active nodes synchronized)", len(syncResp.Nodes))

	// 9. Test gRPC GetGatewayRoutes with Clustered Tunnels
	nodeUUID1, _ := uuid.Parse(enroll1Resp.NodeId)
	t1 := core.Tunnel{
		ID:             uuid.New(),
		NodeID:         nodeUUID1,
		NetworkID:      networkID,
		Name:           "api-t1",
		LocalAddress:   "127.0.0.1:3000",
		PublicHostname: "myapp-api.example.com",
		Protocol:       "http",
	}
	_ = db.Tunnels.Create(ctx, &t1)

	gwRoutesResp, err := node1Client.GetGatewayRoutes(ctx, &v1.GatewayRoutesRequest{})
	if err != nil {
		t.Fatalf("gRPC GetGatewayRoutes failed: %v", err)
	}
	if len(gwRoutesResp.Routes) != 1 || gwRoutesResp.Routes[0].Hostname != "myapp-api.example.com" {
		t.Fatalf("expected route myapp-api.example.com, got %v", gwRoutesResp.Routes)
	}
	t.Logf("✅ gRPC GetGatewayRoutes verified: %s -> %s",
		gwRoutesResp.Routes[0].Hostname, gwRoutesResp.Routes[0].Backends[0].Address)

	// 10. Test Broadcast to Real-Time Event Stream
	bus.Publish(events.Scope{}, "gateway_routes_updated", map[string]string{
		"hostname": "myapp-api.example.com",
	})

	time.Sleep(50 * time.Millisecond)

	evMu.Lock()
	defer evMu.Unlock()
	var foundCustomEvent bool
	for _, evt := range receivedEvents {
		if evt.EventType == "gateway_routes_updated" {
			foundCustomEvent = true
		}
	}

	if !foundCustomEvent {
		t.Fatalf("expected real-time event 'gateway_routes_updated' on gRPC stream")
	}
	t.Log("✅ gRPC Real-Time Streaming verified: Instant push notification received")
}

// testScope maps the authenticated principal to an event scope.
func testScope(ctx context.Context) (events.Scope, error) {
	switch sub := controlauth.FromContext(ctx); {
	case sub != nil && sub.Kind == controlauth.KindEdge:
		return events.Global(), nil
	case sub != nil && sub.Kind == controlauth.KindNode:
		return events.ForNode(uuid.Nil, sub.Node.NetworkID), nil
	}
	return events.Scope{}, status.Error(codes.PermissionDenied, "no scope")
}

// testAuthenticator accepts node tokens and one edge key from the
// authorization metadata, mirroring what the REST server wires in production.
func testAuthenticator(db *store.DB, edgeKey string) Authenticator {
	return func(ctx context.Context) (context.Context, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		vals := md.Get("authorization")
		if len(vals) == 0 {
			return ctx, status.Error(codes.Unauthenticated, "credentials required")
		}
		tok := strings.TrimPrefix(vals[0], "Bearer ")
		if tok == edgeKey {
			return controlauth.WithSubject(ctx, &controlauth.Subject{Kind: controlauth.KindEdge, PoPCode: "KH"}), nil
		}
		node, err := db.Nodes.GetByTokenHash(ctx, controlauth.HashToken(tok))
		if err != nil {
			return ctx, status.Error(codes.Unauthenticated, "invalid token")
		}
		return controlauth.WithSubject(ctx, &controlauth.Subject{Kind: controlauth.KindNode, Node: node}), nil
	}
}
