package grpc

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	v1 "github.com/cubis/zro/api/proto/v1"
	"github.com/cubis/zro/pkg/config"
	"github.com/cubis/zro/pkg/control/events"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/crypto"
	"github.com/cubis/zro/pkg/store"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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
	grpcSrv := grpc.NewServer()
	ctrlServer := NewServer(cfg, db)
	ctrlServer.SetEventSource(events.NewBus(), func(context.Context) (events.Scope, error) { return events.Global(), nil })
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

	// 4. Test Real-time Streaming Events
	var receivedEvents []*v1.MeshEvent
	var evMu sync.Mutex
	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()

	go func() {
		_ = client.StreamEvents(streamCtx, "gateway", "gw1", func(evt *v1.MeshEvent) {
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

	// 6. Test gRPC ReportProbes
	probeResp, err := client.ReportProbes(ctx, &v1.ProbeReportRequest{
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
	discResp, err := client.DiscoverP2P(ctx, &v1.P2PDiscoverRequest{
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
	syncResp, err := client.SyncEdgeMesh(ctx, &v1.EdgeSyncRequest{PopCode: "KH"})
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
		Name:           "api-t1",
		LocalAddress:   "127.0.0.1:3000",
		PublicHostname: "myapp-api.example.com",
		Protocol:       "http",
	}
	_ = db.Tunnels.Create(ctx, &t1)

	gwRoutesResp, err := client.GetGatewayRoutes(ctx, &v1.GatewayRoutesRequest{})
	if err != nil {
		t.Fatalf("gRPC GetGatewayRoutes failed: %v", err)
	}
	if len(gwRoutesResp.Routes) != 1 || gwRoutesResp.Routes[0].Hostname != "myapp-api.example.com" {
		t.Fatalf("expected route myapp-api.example.com, got %v", gwRoutesResp.Routes)
	}
	t.Logf("✅ gRPC GetGatewayRoutes verified: %s -> %s",
		gwRoutesResp.Routes[0].Hostname, gwRoutesResp.Routes[0].Backends[0].Address)

	// 10. Test Broadcast to Real-Time Event Stream
	ctrlServer.BroadcastEvent("gateway_routes_updated", map[string]string{
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
