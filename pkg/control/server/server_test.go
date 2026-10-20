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

func TestSmartRoutingAndP2PDiscovery(t *testing.T) {
	ctx := context.Background()
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}

	secretKey := "test-p2p-secret-key"
	cfg := &config.ControlPlaneConfig{
		ListenAddr:    ":8443",
		PublicURL:     "http://localhost:8443",
		SecretKey:     secretKey,
		DefaultCIDRv4: "100.64.0.0/16",
		DefaultCIDRv6: "fd00:cafe::/64",
	}

	srv := NewServer(cfg, db)

	// 1. Create PoPs (KH and SG)
	popKH := &core.EdgePoP{
		ID:             uuid.New(),
		PoPCode:        "KH",
		Region:         "Phnom Penh",
		PublicEndpoint: "173.1.1.1:51820",
		PublicKey:      "kh-pubkey=",
		IsHealthy:      true,
		Weight:         100,
	}
	_ = db.EdgePoPs.Create(ctx, popKH)

	popSG := &core.EdgePoP{
		ID:             uuid.New(),
		PoPCode:        "SG",
		Region:         "Singapore",
		PublicEndpoint: "123.1.1.1:51820",
		PublicKey:      "sg-pubkey=",
		IsHealthy:      true,
		Weight:         100,
	}
	_ = db.EdgePoPs.Create(ctx, popSG)

	// 2. Create Overlay Network
	netID := core.GenerateNetworkID()
	net := &core.Network{
		ID:        netID,
		Name:      "Mesh-P2P",
		IPv4CIDR:  "100.64.0.0/16",
		IPv6CIDR:  "fd00:cafe::/64",
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = db.Networks.Create(ctx, net)

	// 3. Enroll Node 1 with Pre-Enrollment Probe Telemetry (KH=4ms, SG=38ms)
	kp1, _ := crypto.GenerateKeyPair()
	tok1 := crypto.GenerateEnrollmentToken(secretKey, netID, "client-kh", 1*time.Hour, kp1.PublicKey)

	enroll1Req := EnrollRequest{
		Token:     tok1,
		PublicKey: kp1.PublicKey,
		Hostname:  "client-kh",
		NodeType:  core.NodeTypePeer,
		Endpoints: core.StringList{"203.0.113.10:51820"},
		Probes: []core.LatencySample{
			{PoPCode: "KH", RTT: 4 * time.Millisecond, PacketLoss: 0.0, Timestamp: time.Now()},
			{PoPCode: "SG", RTT: 38 * time.Millisecond, PacketLoss: 0.0, Timestamp: time.Now()},
		},
	}
	body1, _ := json.Marshal(enroll1Req)
	req1 := httptest.NewRequest("POST", "/api/v1/enroll", bytes.NewReader(body1))
	rec1 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec1, req1)

	var res1 EnrollResponse
	_ = json.NewDecoder(rec1.Body).Decode(&res1)

	// Smart Routing check: Node 1 must be delegated to Edge KH as Primary due to lower RTT
	if res1.PrimaryPoP.PoPCode != "KH" {
		t.Fatalf("expected PrimaryPoP to be KH (RTT 4ms vs 38ms), got %s", res1.PrimaryPoP.PoPCode)
	}

	// 4. Enroll Node 2 with Pre-Enrollment Probe Telemetry (KH=42ms, SG=3ms)
	kp2, _ := crypto.GenerateKeyPair()
	tok2 := crypto.GenerateEnrollmentToken(secretKey, netID, "target-sg", 1*time.Hour, kp2.PublicKey)

	enroll2Req := EnrollRequest{
		Token:     tok2,
		PublicKey: kp2.PublicKey,
		Hostname:  "target-sg",
		NodeType:  core.NodeTypePeer,
		Endpoints: core.StringList{"198.51.100.22:51820"},
		Probes: []core.LatencySample{
			{PoPCode: "KH", RTT: 42 * time.Millisecond, PacketLoss: 0.0, Timestamp: time.Now()},
			{PoPCode: "SG", RTT: 3 * time.Millisecond, PacketLoss: 0.0, Timestamp: time.Now()},
		},
	}
	body2, _ := json.Marshal(enroll2Req)
	req2 := httptest.NewRequest("POST", "/api/v1/enroll", bytes.NewReader(body2))
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, req2)

	var res2 EnrollResponse
	_ = json.NewDecoder(rec2.Body).Decode(&res2)

	// Smart Routing check: Node 2 must be delegated to Edge SG as Primary
	if res2.PrimaryPoP.PoPCode != "SG" {
		t.Fatalf("expected PrimaryPoP to be SG (RTT 3ms vs 42ms), got %s", res2.PrimaryPoP.PoPCode)
	}

	// 5. Test P2P Discovery (Section 5 Steps 8-10): Client requests P2P Discovery for Target
	p2pDiscReq := P2PDiscoverRequest{
		InitiatorNodeID:    res1.NodeID,
		TargetOverlayIP:    res2.OverlayIPv4,
		InitiatorEndpoints: core.StringList{"203.0.113.10:51820"},
	}
	discBody, _ := json.Marshal(p2pDiscReq)
	discReq := httptest.NewRequest("POST", "/api/v1/p2p/discover", bytes.NewReader(discBody))
	discRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(discRec, discReq)

	if discRec.Code != http.StatusOK {
		t.Fatalf("expected P2P discovery 200 OK, got %d: %s", discRec.Code, discRec.Body.String())
	}

	var discResp P2PDiscoverResponse
	if err := json.NewDecoder(discRec.Body).Decode(&discResp); err != nil {
		t.Fatalf("failed to decode P2P discovery response: %v", err)
	}

	if discResp.TargetPublicKey != kp2.PublicKey {
		t.Fatalf("expected target pubkey %s, got %s", kp2.PublicKey, discResp.TargetPublicKey)
	}
	if len(discResp.TargetEndpoints) == 0 || discResp.TargetEndpoints[0] != "198.51.100.22:51820" {
		t.Fatalf("expected target endpoint 198.51.100.22:51820, got %v", discResp.TargetEndpoints)
	}
	if discResp.PrimaryPoP == nil || discResp.PrimaryPoP.PoPCode != "SG" {
		t.Fatalf("expected target primary relay fallback to be SG, got %v", discResp.PrimaryPoP)
	}
}
