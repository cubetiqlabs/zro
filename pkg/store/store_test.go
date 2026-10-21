package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cubis/zro/pkg/core"
	"github.com/google/uuid"
)

func TestStoreRepositories(t *testing.T) {
	ctx := context.Background()
	db, err := NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to initialize in-memory SQLite: %v", err)
	}

	// 1. Create Tenant
	tenant := &core.Tenant{
		ID:        uuid.New(),
		Name:      "Cubis Tech",
		Slug:      "cubis",
		APIKey:    "test-api-key-12345",
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := db.Tenants.Create(ctx, tenant); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// 2. Create Network
	net := &core.Network{
		ID:        core.GenerateNetworkID(),
		TenantID:  tenant.ID,
		Name:      "Production Mesh",
		Slug:      "prod",
		IPv4CIDR:  "100.64.0.0/16",
		IPv6CIDR:  "fd00:cafe:1::/64",
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := db.Networks.Create(ctx, net); err != nil {
		t.Fatalf("failed to create network: %v", err)
	}

	// 3. Create Edge PoP
	pop := &core.EdgePoP{
		ID:             uuid.New(),
		PoPCode:        "KH",
		Region:         "Asia/Phnom_Penh",
		PublicEndpoint: "173.1.1.1:51820",
		PublicKey:      "9X7j3W+fakePublicKey123=",
		IsHealthy:      true,
		Weight:         100,
		LastSeenAt:     time.Now(),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	if err := db.EdgePoPs.Create(ctx, pop); err != nil {
		t.Fatalf("failed to create edge pop: %v", err)
	}

	// 4. Create Node
	node := &core.Node{
		ID:            uuid.New(),
		NetworkID:     net.ID,
		Hostname:      "app-kh-01",
		PublicKey:     "4M5k7Y+fakeNodePubKey=",
		OverlayIPv4:   "100.64.0.10",
		OverlayIPv6:   "fd00:cafe:1::10",
		AssignedPoPID: &pop.ID,
		NodeType:      core.NodeTypePeer,
		Tags:          core.StringList{"tag:web", "env:prod"},
		IsActive:      true,
		LastSeenAt:    time.Now(),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := db.Nodes.Create(ctx, node); err != nil {
		t.Fatalf("failed to create node: %v", err)
	}

	// 5. Query and verify relations
	fetchedNode, err := db.Nodes.GetByID(ctx, node.ID)
	if err != nil {
		t.Fatalf("failed to fetch node: %v", err)
	}
	if fetchedNode.AssignedPoP == nil || fetchedNode.AssignedPoP.PoPCode != "KH" {
		t.Fatalf("expected preloaded AssignedPoP with code KH, got %+v", fetchedNode.AssignedPoP)
	}

	// 6. Test Allocated IPs
	ips, err := db.Nodes.ListAllocatedIPs(ctx, net.ID)
	if err != nil {
		t.Fatalf("failed to list allocated IPs: %v", err)
	}
	if len(ips) != 1 || ips[0] != "100.64.0.10" {
		t.Fatalf("expected ['100.64.0.10'], got %v", ips)
	}
}

func TestEnrollmentRedeemSingleUse(t *testing.T) {
	db, err := NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)

	if err := db.Enrollments.Redeem(ctx, "n1", "keyA", exp); err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	if err := db.Enrollments.Redeem(ctx, "n1", "keyA", exp); err != nil {
		t.Fatalf("same key must be idempotent: %v", err)
	}
	if err := db.Enrollments.Redeem(ctx, "n1", "keyB", exp); !errors.Is(err, core.ErrTokenReused) {
		t.Fatalf("different key must be rejected, got %v", err)
	}
}
