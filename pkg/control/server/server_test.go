package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cubis/zro/pkg/config"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/crypto"
	"github.com/cubis/zro/pkg/store"
	"github.com/google/uuid"
)

func TestServerEnrollmentFlow(t *testing.T) {
	ctx := context.Background()
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}

	secretKey := "test-super-secret-key"
	cfg := &config.ControlPlaneConfig{
		ListenAddr:    ":8443",
		PublicURL:     "https://zro-plane.cubis.tech:443",
		SecretKey:     secretKey,
		DefaultCIDRv4: "100.64.0.0/16",
		DefaultCIDRv6: "fd00:cafe::/64",
	}

	// 1. Seed tenant, network, and edge PoPs (KH and SG)
	tenant := &core.Tenant{
		ID:        uuid.New(),
		Name:      "Cubis Tech",
		Slug:      "cubis",
		APIKey:    "test-key",
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = db.Tenants.Create(ctx, tenant)

	network := &core.Network{
		ID:        core.GenerateNetworkID(),
		TenantID:  tenant.ID,
		Name:      "Prod Mesh",
		Slug:      "prod",
		IPv4CIDR:  "100.64.0.0/16",
		IPv6CIDR:  "fd00:cafe:1::/64",
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = db.Networks.Create(ctx, network)

	popKH := &core.EdgePoP{
		ID:             uuid.New(),
		PoPCode:        "KH",
		Region:         "Asia/Phnom_Penh",
		PublicEndpoint: "173.1.1.1:51820",
		PublicKey:      "kh-public-key=",
		IsHealthy:      true,
		Weight:         100,
		LastSeenAt:     time.Now(),
	}
	_ = db.EdgePoPs.Create(ctx, popKH)

	popSG := &core.EdgePoP{
		ID:             uuid.New(),
		PoPCode:        "SG",
		Region:         "Asia/Singapore",
		PublicEndpoint: "123.1.1.1:51820",
		PublicKey:      "sg-public-key=",
		IsHealthy:      true,
		Weight:         90,
		LastSeenAt:     time.Now(),
	}
	_ = db.EdgePoPs.Create(ctx, popSG)

	srv := NewServer(cfg, db)

	// 2. Test Health check
	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected health status 200, got %d", rec.Code)
	}

	// 3. Test Enroll Node
	kp, _ := crypto.GenerateKeyPair()
	token := crypto.GenerateEnrollmentToken(secretKey, network.ID, "node-kh-01", 10*time.Minute, kp.PublicKey)

	enrollReq := EnrollRequest{
		Token:     token,
		PublicKey: kp.PublicKey,
		Hostname:  "node-kh-01",
		NodeType:  core.NodeTypePeer,
		Tags:      core.StringList{"tag:web"},
		Endpoints: core.StringList{"192.168.1.50:51820"},
	}

	bodyBytes, _ := json.Marshal(enrollReq)
	req = httptest.NewRequest("POST", "/api/v1/enroll", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected enroll 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var enrollResp EnrollResponse
	if err := json.NewDecoder(rec.Body).Decode(&enrollResp); err != nil {
		t.Fatalf("failed to parse enroll response: %v", err)
	}

	if enrollResp.OverlayIPv4 != "100.64.0.2" {
		t.Fatalf("expected first allocated IP to be 100.64.0.2, got %s", enrollResp.OverlayIPv4)
	}

	if enrollResp.PrimaryPoP.PoPCode == "" {
		t.Fatalf("expected delegated PrimaryPoP, got empty")
	}
}
