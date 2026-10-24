package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cubetiqlabs/zro/pkg/config"
	"github.com/cubetiqlabs/zro/pkg/control/events"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/cubetiqlabs/zro/pkg/crypto"
	"github.com/cubetiqlabs/zro/pkg/store"
	"github.com/google/uuid"
	"golang.org/x/net/websocket"
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
	discReq.Header.Set("Authorization", "Bearer "+res1.NodeToken)
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

func TestMeshGraphAndEdgeHeartbeatsAndACLs(t *testing.T) {
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}

	secretKey := "test-secret"
	cfg := &config.ControlPlaneConfig{
		ListenAddr:    ":8443",
		PublicURL:     "http://localhost:8443",
		SecretKey:     secretKey,
		DefaultCIDRv4: "100.64.0.0/16",
		DefaultCIDRv6: "fd00:cafe::/64",
	}

	srv := NewServer(cfg, db)

	// 1. Create Network
	netReqBody, _ := json.Marshal(CreateNetworkRequest{
		Name:     "Mesh Graph VPC",
		IPv4CIDR: "100.64.0.0/10",
		IPv6CIDR: "fd00:cafe::/64",
	})
	netReq := httptest.NewRequest("POST", "/api/v1/networks", bytes.NewReader(netReqBody))
	netRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(netRec, netReq)
	if netRec.Code != http.StatusCreated {
		t.Fatalf("failed to create network: %s", netRec.Body.String())
	}
	var createdNet core.Network
	_ = json.NewDecoder(netRec.Body).Decode(&createdNet)

	// 2. Register Edge PoP and send Heartbeat
	popReqBody, _ := json.Marshal(RegisterEdgePoPRequest{
		PoPCode:        "KH",
		Region:         "Cambodia",
		PublicEndpoint: "173.1.1.1:51820",
		PublicKey:      "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		Weight:         100,
	})
	popReq := httptest.NewRequest("POST", "/api/v1/edge/register", bytes.NewReader(popReqBody))
	popRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(popRec, popReq)
	if popRec.Code != http.StatusOK {
		t.Fatalf("failed to register edge pop: %s", popRec.Body.String())
	}

	hbBody, _ := json.Marshal(EdgeHeartbeatRequest{
		PoPCode:        "KH",
		Status:         "online",
		PeersCount:     3,
		RTTMs:          1.5,
		PublicEndpoint: "173.1.1.1:51820",
	})
	hbReq := httptest.NewRequest("POST", "/api/v1/edge/heartbeat", bytes.NewReader(hbBody))
	hbRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(hbRec, hbReq)
	if hbRec.Code != http.StatusOK {
		t.Fatalf("failed to process edge heartbeat: %s", hbRec.Body.String())
	}

	// 3. Test ACL API (Microsegmentation: Node 2 -> Node 1 on port 5432 ALLOW)
	aclReqBody, _ := json.Marshal(CreateACLRuleRequest{
		NetworkID: createdNet.ID,
		Priority:  10,
		SourceIP:  "100.64.0.11",
		DestIP:    "100.64.0.10",
		Protocol:  "tcp",
		Ports:     "5432",
		Action:    core.ACLActionAllow,
	})
	aclReq := httptest.NewRequest("POST", "/api/v1/acl/rules", bytes.NewReader(aclReqBody))
	aclRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(aclRec, aclReq)
	if aclRec.Code != http.StatusCreated {
		t.Fatalf("failed to create ACL rule: %s", aclRec.Body.String())
	}

	listAclReq := httptest.NewRequest("GET", "/api/v1/acl/rules?network_id="+createdNet.ID, nil)
	listAclRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(listAclRec, listAclReq)
	var rulePage Page[core.ACLRule]
	_ = json.NewDecoder(listAclRec.Body).Decode(&rulePage)
	rules := rulePage.Items
	if len(rules) != 1 || rules[0].Ports != "5432" {
		t.Fatalf("expected 1 ACL rule on port 5432, got %v", rules)
	}

	// 4. Enroll Node 1 (hosts postgres: 5432/tcp) and Node 2
	kp1, _ := crypto.GenerateKeyPair()
	tok1 := crypto.GenerateEnrollmentToken(secretKey, createdNet.ID, "node1", 1*time.Hour, kp1.PublicKey)
	enroll1Body, _ := json.Marshal(EnrollRequest{
		Token:        tok1,
		PublicKey:    kp1.PublicKey,
		Hostname:     "node1",
		NodeType:     core.NodeTypePeer,
		AllowedPorts: core.StringList{"5432/tcp"},
	})
	eReq1 := httptest.NewRequest("POST", "/api/v1/enroll", bytes.NewReader(enroll1Body))
	eRec1 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(eRec1, eReq1)
	var eRes1 EnrollResponse
	_ = json.NewDecoder(eRec1.Body).Decode(&eRes1)

	kp2, _ := crypto.GenerateKeyPair()
	tok2 := crypto.GenerateEnrollmentToken(secretKey, createdNet.ID, "node2", 1*time.Hour, kp2.PublicKey)
	enroll2Body, _ := json.Marshal(EnrollRequest{
		Token:     tok2,
		PublicKey: kp2.PublicKey,
		Hostname:  "node2",
		NodeType:  core.NodeTypePeer,
	})
	eReq2 := httptest.NewRequest("POST", "/api/v1/enroll", bytes.NewReader(enroll2Body))
	eRec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(eRec2, eReq2)
	var eRes2 EnrollResponse
	_ = json.NewDecoder(eRec2.Body).Decode(&eRes2)

	// 5. Query Real-Time Mesh Topology Graph
	graphReq := httptest.NewRequest("GET", "/api/v1/mesh/graph?network_id="+createdNet.ID, nil)
	graphRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(graphRec, graphReq)

	if graphRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for mesh graph, got %d: %s", graphRec.Code, graphRec.Body.String())
	}

	var graphResp MeshGraphResponse
	if err := json.NewDecoder(graphRec.Body).Decode(&graphResp); err != nil {
		t.Fatalf("failed to decode mesh graph response: %v", err)
	}

	if len(graphResp.Nodes) < 3 { // pop-KH, node1, node2
		t.Fatalf("expected at least 3 nodes in graph, got %d", len(graphResp.Nodes))
	}

	var foundNode1, foundNode2, foundPoPKH bool
	for _, n := range graphResp.Nodes {
		if n.Hostname == "node1" {
			foundNode1 = true
			if len(n.AllowedPorts) == 0 || n.AllowedPorts[0] != "5432/tcp" {
				t.Fatalf("expected node1 allowed port 5432/tcp, got %v", n.AllowedPorts)
			}
		}
		if n.Hostname == "node2" {
			foundNode2 = true
		}
		if n.Hostname == "pop-KH" {
			foundPoPKH = true
			if n.Status != "online" {
				t.Fatalf("expected pop-KH to be online after heartbeat, got %s", n.Status)
			}
		}
	}

	if !foundNode1 || !foundNode2 || !foundPoPKH {
		t.Fatalf("missing nodes in mesh graph (node1: %v, node2: %v, pop-KH: %v)", foundNode1, foundNode2, foundPoPKH)
	}

	// Check edges
	if len(graphResp.Edges) == 0 {
		t.Fatalf("expected edges in graph, got 0")
	}
	t.Logf("✅ Real-Time Mesh Topology Graph verified: %d nodes, %d edges", len(graphResp.Nodes), len(graphResp.Edges))
}

func TestServerAuthAndTenantIsolation(t *testing.T) {
	ctx := context.Background()
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}

	secretKey := "test-auth-cluster-secret"
	edgeKey := "edge-secret-key-123"
	cfg := &config.ControlPlaneConfig{
		ListenAddr:    ":8443",
		PublicURL:     "https://zro-plane.cubis.tech:443",
		SecretKey:     secretKey,
		EdgeAPIKey:    edgeKey,
		RequireAuth:   true, // Require explicit authentication
		DefaultCIDRv4: "100.64.0.0/16",
		DefaultCIDRv6: "fd00:cafe::/64",
	}

	// 1. Create two distinct tenants
	tenantA := &core.Tenant{
		ID:        uuid.New(),
		Name:      "Tenant Alpha",
		Slug:      "alpha",
		APIKey:    "key_alpha_12345",
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = db.Tenants.Create(ctx, tenantA)

	tenantB := &core.Tenant{
		ID:        uuid.New(),
		Name:      "Tenant Beta",
		Slug:      "beta",
		APIKey:    "key_beta_67890",
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = db.Tenants.Create(ctx, tenantB)

	srv := NewServer(cfg, db)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Case 1: Unauthenticated request when RequireAuth=true -> MUST RETURN 401
	rUnauth, _ := http.Get(ts.URL + "/api/v1/networks")
	if rUnauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for unauthenticated request, got %d", rUnauth.StatusCode)
	}
	_ = rUnauth.Body.Close()

	// Case 2: Invalid API key -> MUST RETURN 401
	reqInvalid, _ := http.NewRequest("GET", ts.URL+"/api/v1/networks", nil)
	reqInvalid.Header.Set("Authorization", "Bearer invalid-key")
	rInvalid, _ := http.DefaultClient.Do(reqInvalid)
	if rInvalid.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid API key, got %d", rInvalid.StatusCode)
	}
	_ = rInvalid.Body.Close()

	// Case 3: Tenant Alpha creates a network
	createBody, _ := json.Marshal(CreateNetworkRequest{
		Name: "Alpha VPC",
	})
	reqCreateA, _ := http.NewRequest("POST", ts.URL+"/api/v1/networks", bytes.NewReader(createBody))
	reqCreateA.Header.Set("Authorization", "Bearer key_alpha_12345")
	reqCreateA.Header.Set("Content-Type", "application/json")
	rCreateA, err := http.DefaultClient.Do(reqCreateA)
	if err != nil || rCreateA.StatusCode != http.StatusCreated {
		t.Fatalf("failed to create network for Tenant Alpha: %v", err)
	}
	var netA core.Network
	_ = json.NewDecoder(rCreateA.Body).Decode(&netA)
	_ = rCreateA.Body.Close()

	if netA.TenantID != tenantA.ID {
		t.Fatalf("expected network to be owned by Tenant Alpha (%s), got %s", tenantA.ID, netA.TenantID)
	}

	// Case 4: Tenant Beta lists networks -> MUST NOT see Tenant Alpha's network
	reqListB, _ := http.NewRequest("GET", ts.URL+"/api/v1/networks", nil)
	reqListB.Header.Set("X-API-Key", "key_beta_67890")
	rListB, _ := http.DefaultClient.Do(reqListB)
	var netsB Page[core.Network]
	_ = json.NewDecoder(rListB.Body).Decode(&netsB)
	_ = rListB.Body.Close()

	if len(netsB.Items) != 0 {
		t.Fatalf("Tenant Beta should see 0 networks, got %d", len(netsB.Items))
	}

	// Case 5: Tenant Beta attempts to create an ACL rule on Tenant Alpha's network -> MUST RETURN 403 Forbidden
	aclBody, _ := json.Marshal(CreateACLRuleRequest{
		NetworkID: netA.ID,
		SourceIP:  "*",
		DestIP:    "*",
		Ports:     "80",
		Action:    core.ACLActionAllow,
	})
	reqAclB, _ := http.NewRequest("POST", ts.URL+"/api/v1/acl/rules", bytes.NewReader(aclBody))
	reqAclB.Header.Set("Authorization", "Bearer key_beta_67890")
	reqAclB.Header.Set("Content-Type", "application/json")
	rAclB, _ := http.DefaultClient.Do(reqAclB)
	if rAclB.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when Tenant Beta creates ACL on Tenant Alpha network, got %d", rAclB.StatusCode)
	}
	_ = rAclB.Body.Close()

	// Case 5b: event streams are tenant-scoped and cross-tenant ACL deletes are hidden
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/v1/ws"
	dialWS := func(key string) *websocket.Conn {
		wsCfg, _ := websocket.NewConfig(wsURL, ts.URL)
		wsCfg.Header.Set("Authorization", "Bearer "+key)
		conn, err := websocket.DialConfig(wsCfg)
		if err != nil {
			t.Fatalf("websocket dial for %s failed: %v", key, err)
		}
		var hello events.Message
		_ = websocket.JSON.Receive(conn, &hello)
		return conn
	}
	connA, connB := dialWS("key_alpha_12345"), dialWS("key_beta_67890")
	defer connA.Close()
	defer connB.Close()

	aclOwn, _ := json.Marshal(CreateACLRuleRequest{NetworkID: netA.ID, SourceIP: "*", DestIP: "*", Ports: "80", Action: core.ACLActionAllow})
	reqOwn, _ := http.NewRequest("POST", ts.URL+"/api/v1/acl/rules", bytes.NewReader(aclOwn))
	reqOwn.Header.Set("Authorization", "Bearer key_alpha_12345")
	reqOwn.Header.Set("Content-Type", "application/json")
	rOwn, err := http.DefaultClient.Do(reqOwn)
	if err != nil || rOwn.StatusCode != http.StatusCreated {
		t.Fatalf("Tenant Alpha failed to create its ACL rule: %v", err)
	}
	var ruleA core.ACLRule
	_ = json.NewDecoder(rOwn.Body).Decode(&ruleA)
	_ = rOwn.Body.Close()

	_ = connA.SetReadDeadline(time.Now().Add(2 * time.Second))
	var evA events.Message
	if err := websocket.JSON.Receive(connA, &evA); err != nil || evA.Event != "acl_rules_updated" {
		t.Fatalf("Tenant Alpha should receive its own acl_rules_updated event, got %+v err=%v", evA, err)
	}
	_ = connB.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var evB events.Message
	if err := websocket.JSON.Receive(connB, &evB); err == nil {
		t.Fatalf("Tenant Beta must not receive Tenant Alpha's events, got %+v", evB)
	}

	delRule := func(key string) int {
		req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/acl/rules/"+ruleA.ID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := delRule("key_beta_67890"); code != http.StatusNotFound {
		t.Fatalf("expected 404 when Tenant Beta deletes Alpha's rule, got %d", code)
	}
	if code := delRule("key_alpha_12345"); code != http.StatusOK {
		t.Fatalf("expected 200 when Tenant Alpha deletes its rule, got %d", code)
	}

	// Case 6: Edge PoP authentication
	// 6a. Register edge without key when RequireAuth=true -> 401
	kpEdge, _ := crypto.GenerateKeyPair()
	edgeRegBody, _ := json.Marshal(RegisterEdgePoPRequest{
		PoPCode:        "SG",
		Region:         "Singapore",
		PublicEndpoint: "123.1.1.1:51820",
		PublicKey:      kpEdge.PublicKey,
	})
	rEdgeNoKey, _ := http.Post(ts.URL+"/api/v1/edge/register", "application/json", bytes.NewReader(edgeRegBody))
	if rEdgeNoKey.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for edge registration without key, got %d", rEdgeNoKey.StatusCode)
	}
	_ = rEdgeNoKey.Body.Close()

	// 6b. Register edge with valid EdgeAPIKey -> 200 OK
	reqEdgeValid, _ := http.NewRequest("POST", ts.URL+"/api/v1/edge/register", bytes.NewReader(edgeRegBody))
	reqEdgeValid.Header.Set("Authorization", "Bearer "+edgeKey)
	reqEdgeValid.Header.Set("Content-Type", "application/json")
	rEdgeValid, err := http.DefaultClient.Do(reqEdgeValid)
	if err != nil || rEdgeValid.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for valid edge registration, got %d", rEdgeValid.StatusCode)
	}
	_ = rEdgeValid.Body.Close()
	t.Log("✅ TestServerAuthAndTenantIsolation passed: 401 enforcement, API key validation, multi-tenant isolation, and edge authentication verified")
}

func TestPhase1AuthMatrix(t *testing.T) {
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	const secret = "matrix-secret"
	srv := NewServer(&config.ControlPlaneConfig{
		SecretKey: secret, AdminAPIKey: "admin-key", RequireAuth: true,
		DefaultCIDRv4: "100.64.0.0/16", DefaultCIDRv6: "fd00:cafe::/64",
	}, db)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	do := func(method, path, bearer string, body any) (int, []byte) {
		var rdr *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		} else {
			rdr = bytes.NewReader(nil)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rdr)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return resp.StatusCode, buf.Bytes()
	}

	// Admin API: wrong key is rejected, tenants are created with a one-time key.
	if code, _ := do("GET", "/api/v1/tenants", "nope", nil); code != http.StatusUnauthorized {
		t.Fatalf("wrong admin key: got %d", code)
	}
	mkTenant := func(slug string) (id, key string) {
		code, body := do("POST", "/api/v1/tenants", "admin-key", map[string]string{"name": slug, "slug": slug})
		var out tenantResponse
		_ = json.Unmarshal(body, &out)
		if code != http.StatusCreated || out.APIKey == "" {
			t.Fatalf("create tenant %s: %d %s", slug, code, body)
		}
		return out.ID.String(), out.APIKey
	}
	_, keyA := mkTenant("alpha")
	tenantBID, keyB := mkTenant("beta")
	if _, body := do("GET", "/api/v1/tenants", "admin-key", nil); bytes.Contains(body, []byte(keyA)) {
		t.Fatal("tenant listing must never expose API keys")
	}

	mkNet := func(key string) string {
		code, body := do("POST", "/api/v1/networks", key, CreateNetworkRequest{Name: "n"})
		var n core.Network
		_ = json.Unmarshal(body, &n)
		if code != http.StatusCreated {
			t.Fatalf("create network: %d %s", code, body)
		}
		return n.ID
	}
	netA, netB := mkNet(keyA), mkNet(keyB)

	enrollNode := func(netID, host string) (EnrollResponse, string) {
		kp, _ := crypto.GenerateKeyPair()
		tok := crypto.GenerateEnrollmentToken(secret, netID, host, time.Hour, kp.PublicKey)
		code, body := do("POST", "/api/v1/enroll", "", EnrollRequest{Token: tok, PublicKey: kp.PublicKey, Hostname: host})
		var resp EnrollResponse
		_ = json.Unmarshal(body, &resp)
		if code != http.StatusOK || resp.NodeToken == "" {
			t.Fatalf("enroll %s: %d %s", host, code, body)
		}
		return resp, tok
	}
	nodeA, tokA := enrollNode(netA, "a1")
	nodeB, _ := enrollNode(netB, "b1")

	// Enrollment: hostname mismatch, wrong role and replay by another key are refused.
	kp2, _ := crypto.GenerateKeyPair()
	if code, _ := do("POST", "/api/v1/enroll", "", EnrollRequest{Token: tokA, PublicKey: kp2.PublicKey}); code != http.StatusUnauthorized {
		t.Fatalf("token bound to another key must fail, got %d", code)
	}
	unbound, _ := crypto.SignEnrollmentToken(secret, crypto.EnrollmentTokenPayload{NetworkID: netA, Hostname: "x", Expiry: time.Now().Add(time.Hour).Unix()})
	kp3, _ := crypto.GenerateKeyPair()
	if code, _ := do("POST", "/api/v1/enroll", "", EnrollRequest{Token: unbound, PublicKey: kp2.PublicKey, Hostname: "x"}); code != http.StatusOK {
		t.Fatalf("first redemption should succeed, got %d", code)
	}
	if code, _ := do("POST", "/api/v1/enroll", "", EnrollRequest{Token: unbound, PublicKey: kp3.PublicKey, Hostname: "x"}); code != http.StatusConflict {
		t.Fatalf("replay by another key must conflict, got %d", code)
	}
	if code, _ := do("POST", "/api/v1/enroll", "", EnrollRequest{Token: unbound, PublicKey: kp2.PublicKey, Hostname: "x", NodeType: core.NodeTypeGateway}); code != http.StatusForbidden {
		t.Fatalf("peer token must not enroll a gateway, got %d", code)
	}

	// Node endpoints demand a token.
	for _, path := range []string{"/api/v1/gateway/routes", "/api/v1/network/" + netA + "/peers", "/api/v1/tunnels"} {
		if code, _ := do("GET", path, "", nil); code != http.StatusUnauthorized {
			t.Fatalf("%s without token: got %d", path, code)
		}
	}
	if code, _ := do("POST", "/api/v1/probes", "", core.LatencySample{PoPCode: "KH"}); code != http.StatusUnauthorized {
		t.Fatalf("probes without token: got %d", code)
	}

	// Cross-network reads are denied; probing another network's node IP finds nothing.
	if code, _ := do("GET", "/api/v1/network/"+netA+"/peers", nodeB.NodeToken, nil); code != http.StatusForbidden {
		t.Fatalf("peers of another network: got %d", code)
	}
	if code, _ := do("POST", "/api/v1/p2p/discover", nodeB.NodeToken, P2PDiscoverRequest{TargetNodeID: &nodeA.NodeID}); code != http.StatusNotFound {
		t.Fatalf("p2p to another network's node: got %d", code)
	}

	// Tunnels: owned by the caller's network, hostnames cannot be hijacked, bad input rejected.
	tun := core.Tunnel{PublicHostname: "App.Example.com", LocalAddress: "127.0.0.1:8080"}
	if code, body := do("POST", "/api/v1/tunnels", nodeA.NodeToken, tun); code != http.StatusCreated {
		t.Fatalf("register tunnel: %d %s", code, body)
	}
	if code, _ := do("POST", "/api/v1/tunnels", nodeB.NodeToken, tun); code != http.StatusConflict {
		t.Fatalf("hostname hijack must conflict, got %d", code)
	}
	if code, _ := do("POST", "/api/v1/tunnels", nodeA.NodeToken, core.Tunnel{PublicHostname: "bad host!", LocalAddress: "127.0.0.1:1"}); code != http.StatusBadRequest {
		t.Fatalf("invalid hostname: got %d", code)
	}
	_, body := do("GET", "/api/v1/gateway/routes", nodeB.NodeToken, nil)
	if bytes.Contains(body, []byte("app.example.com")) {
		t.Fatal("gateway routes leaked another network's tunnel")
	}
	var list []core.Tunnel
	_, body = do("GET", "/api/v1/tunnels", nodeA.NodeToken, nil)
	_ = json.Unmarshal(body, &list)
	if len(list) != 1 {
		t.Fatalf("expected 1 tunnel, got %d", len(list))
	}
	if code, _ := do("DELETE", "/api/v1/tunnels/"+list[0].ID.String(), nodeB.NodeToken, nil); code != http.StatusNotFound {
		t.Fatalf("deleting another node's tunnel: got %d", code)
	}
	if code, _ := do("DELETE", "/api/v1/tunnels/"+list[0].ID.String(), nodeA.NodeToken, nil); code != http.StatusNoContent {
		t.Fatalf("deleting own tunnel: got %d", code)
	}

	// Access policy: tenants write rules, nodes receive only their own network's,
	// and malformed rules are refused instead of silently mis-matching.
	if code, body := do("POST", "/api/v1/acl/rules", keyA, CreateACLRuleRequest{NetworkID: netA, SourceTag: "tag:web", DestTag: "tag:db", Ports: "5432", Action: core.ACLActionAllow}); code != http.StatusCreated {
		t.Fatalf("create rule: %d %s", code, body)
	}
	if code, _ := do("POST", "/api/v1/acl/rules", keyA, CreateACLRuleRequest{NetworkID: netA, SourceIP: "10.0.0.0/99", Action: core.ACLActionAllow}); code != http.StatusBadRequest {
		t.Fatalf("a malformed CIDR must be rejected, got %d", code)
	}
	if code, _ := do("POST", "/api/v1/acl/rules", keyA, CreateACLRuleRequest{NetworkID: netA, Ports: "80,x", Action: core.ACLActionAllow}); code != http.StatusBadRequest {
		t.Fatalf("a malformed port list must be rejected, got %d", code)
	}
	var policyA, policyB []core.ACLRule
	_, body = do("GET", "/api/v1/acl/policy", nodeA.NodeToken, nil)
	_ = json.Unmarshal(body, &policyA)
	_, body = do("GET", "/api/v1/acl/policy", nodeB.NodeToken, nil)
	_ = json.Unmarshal(body, &policyB)
	if len(policyA) != 1 || policyA[0].SourceTag != "tag:web" || len(policyB) != 0 {
		t.Fatalf("each node must get exactly its own network's rules, got A=%d B=%d", len(policyA), len(policyB))
	}
	if code, _ := do("GET", "/api/v1/acl/policy", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("policy without a node token: got %d", code)
	}

	// Leaving the mesh invalidates the token and frees the node.
	if code, _ := do("DELETE", "/api/v1/node", nodeB.NodeToken, nil); code != http.StatusNoContent {
		t.Fatalf("deregister: got %d", code)
	}
	if code, _ := do("GET", "/api/v1/tunnels", nodeB.NodeToken, nil); code != http.StatusUnauthorized {
		t.Fatalf("token of a deregistered node must be rejected, got %d", code)
	}

	// Mesh graph honors ownership; no cross-tenant default.
	if code, _ := do("GET", "/api/v1/mesh/graph?network_id="+netA, keyB, nil); code != http.StatusForbidden {
		t.Fatalf("graph of another tenant's network: got %d", code)
	}
	if code, _ := do("GET", "/api/v1/mesh/graph?network_id="+netB, keyB, nil); code != http.StatusOK {
		t.Fatalf("graph of own network: got %d", code)
	}

	// Key rotation invalidates the old key; hashed storage still authenticates the new one.
	code, body := do("POST", "/api/v1/tenants/"+tenantBID+"/rotate-key", "admin-key", nil)
	var rotated tenantResponse
	_ = json.Unmarshal(body, &rotated)
	if code != http.StatusOK || rotated.APIKey == "" || rotated.APIKey == keyB {
		t.Fatalf("rotate: %d %s", code, body)
	}
	if code, _ := do("GET", "/api/v1/networks", keyB, nil); code != http.StatusUnauthorized {
		t.Fatalf("old key must stop working, got %d", code)
	}
	if code, _ := do("GET", "/api/v1/networks", rotated.APIKey, nil); code != http.StatusOK {
		t.Fatalf("new key must work, got %d", code)
	}
}

func TestEdgePoPClaimAndPerPoPCredentials(t *testing.T) {
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(&config.ControlPlaneConfig{SecretKey: "s", EdgeAPIKey: "shared-edge-key", AdminAPIKey: "admin", RequireAuth: true}, db)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	call := func(method, path, bearer string, body any) (int, []byte) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, ts.URL+path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return resp.StatusCode, buf.Bytes()
	}
	kp, _ := crypto.GenerateKeyPair()
	reg := func(code string) RegisterEdgePoPRequest {
		return RegisterEdgePoPRequest{PoPCode: code, Region: "r", PublicEndpoint: "1.2.3.4:51820", PublicKey: kp.PublicKey}
	}

	// First registration claims the PoP and returns its own credential once.
	code, body := call("POST", "/api/v1/edge/register", "shared-edge-key", reg("KH"))
	var claimed struct {
		PopKey string `json:"pop_key"`
	}
	_ = json.Unmarshal(body, &claimed)
	if code != http.StatusOK || claimed.PopKey == "" {
		t.Fatalf("claim: %d %s", code, body)
	}

	// The shared key can no longer touch a claimed PoP, nor use PoP-only endpoints.
	if code, _ := call("POST", "/api/v1/edge/register", "shared-edge-key", reg("KH")); code != http.StatusForbidden {
		t.Fatalf("shared key overwriting a claimed PoP: got %d", code)
	}
	if code, _ := call("POST", "/api/v1/edge/heartbeat", "shared-edge-key", EdgeHeartbeatRequest{PoPCode: "KH"}); code != http.StatusForbidden {
		t.Fatalf("shared key on heartbeat: got %d", code)
	}
	if code, _ := call("GET", "/api/v1/edge/sync", "shared-edge-key", nil); code != http.StatusForbidden {
		t.Fatalf("shared key on sync: got %d", code)
	}

	// The PoP's own credential works for itself and only for itself.
	if code, _ := call("POST", "/api/v1/edge/register", claimed.PopKey, reg("KH")); code != http.StatusOK {
		t.Fatalf("PoP refreshing its registration: got %d", code)
	}
	if code, _ := call("POST", "/api/v1/edge/heartbeat", claimed.PopKey, EdgeHeartbeatRequest{PoPCode: "KH"}); code != http.StatusOK {
		t.Fatalf("PoP heartbeat: got %d", code)
	}
	_, _ = call("POST", "/api/v1/edge/register", "shared-edge-key", reg("SG"))
	if code, _ := call("POST", "/api/v1/edge/heartbeat", claimed.PopKey, EdgeHeartbeatRequest{PoPCode: "SG"}); code != http.StatusForbidden {
		t.Fatalf("KH credential used for SG: got %d", code)
	}
	if code, _ := call("POST", "/api/v1/edge/register", claimed.PopKey, reg("SG")); code != http.StatusForbidden {
		t.Fatalf("KH credential registering SG: got %d", code)
	}

	// Graceful shutdown marks the PoP offline; an admin reset lets it be re-claimed.
	if code, _ := call("POST", "/api/v1/edge/deregister", claimed.PopKey, nil); code != http.StatusNoContent {
		t.Fatalf("deregister: got %d", code)
	}
	if pop, _ := db.EdgePoPs.GetByPoPCode(context.Background(), "KH"); pop.IsHealthy {
		t.Fatal("deregistered PoP must be offline")
	}
	if code, _ := call("POST", "/api/v1/pops/KH/reset-key", "admin", nil); code != http.StatusNoContent {
		t.Fatalf("reset: got %d", code)
	}
	if code, body := call("POST", "/api/v1/edge/register", "shared-edge-key", reg("KH")); code != http.StatusOK || !bytes.Contains(body, []byte("pop_key")) {
		t.Fatalf("re-claim after reset: %d %s", code, body)
	}
	if code, _ := call("POST", "/api/v1/edge/heartbeat", claimed.PopKey, EdgeHeartbeatRequest{PoPCode: "KH"}); code != http.StatusUnauthorized {
		t.Fatalf("the old credential must be dead after a reset, got %d", code)
	}
}

func TestManagementEndpointsAreTenantScoped(t *testing.T) {
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	const secret = "mgmt-secret"
	srv := NewServer(&config.ControlPlaneConfig{SecretKey: secret, AdminAPIKey: "admin", RequireAuth: true, DefaultCIDRv4: "100.64.0.0/16", DefaultCIDRv6: "fd00:cafe::/64"}, db)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	do := func(method, path, bearer string, body any) (int, []byte) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, ts.URL+path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return resp.StatusCode, buf.Bytes()
	}
	mk := func(slug string) (string, string) {
		_, body := do("POST", "/api/v1/tenants", "admin", map[string]string{"name": slug, "slug": slug})
		var tr tenantResponse
		_ = json.Unmarshal(body, &tr)
		_, nb := do("POST", "/api/v1/networks", tr.APIKey, CreateNetworkRequest{Name: slug})
		var n core.Network
		_ = json.Unmarshal(nb, &n)
		return tr.APIKey, n.ID
	}
	keyA, netA := mk("alpha")
	keyB, netB := mk("beta")

	// Update: owner only; addressing stays immutable.
	if code, _ := do("PATCH", "/api/v1/networks/"+netA, keyB, map[string]string{"name": "hijack"}); code != http.StatusNotFound {
		t.Fatalf("updating another tenant's network: %d", code)
	}
	if code, body := do("PATCH", "/api/v1/networks/"+netA, keyA, map[string]any{"name": "renamed", "dns_domain": "A.Corp.Internal", "ipv4_cidr": "10.0.0.0/8"}); code != http.StatusOK || !bytes.Contains(body, []byte(`"name":"renamed"`)) || bytes.Contains(body, []byte("10.0.0.0/8")) {
		t.Fatalf("owner update: %d %s", code, body)
	}
	if code, _ := do("PATCH", "/api/v1/networks/"+netA, keyA, map[string]string{"dns_domain": "not a domain!"}); code != http.StatusBadRequest {
		t.Fatalf("bad dns_domain: %d", code)
	}

	// Nodes: list and remove, scoped to the owner.
	kp, _ := crypto.GenerateKeyPair()
	tok := crypto.GenerateEnrollmentToken(secret, netA, "n1", time.Hour, kp.PublicKey)
	code, body := do("POST", "/api/v1/enroll", "", EnrollRequest{Token: tok, PublicKey: kp.PublicKey, Hostname: "n1"})
	var enrolled EnrollResponse
	_ = json.Unmarshal(body, &enrolled)
	if code != http.StatusOK {
		t.Fatalf("enroll: %d %s", code, body)
	}
	if code, _ := do("GET", "/api/v1/nodes?network_id="+netA, keyB, nil); code != http.StatusNotFound {
		t.Fatalf("listing another tenant's nodes: %d", code)
	}
	var nodePage Page[core.Node]
	_, body = do("GET", "/api/v1/nodes?network_id="+netA, keyA, nil)
	_ = json.Unmarshal(body, &nodePage)
	nodes := nodePage.Items
	if len(nodes) != 1 {
		t.Fatalf("expected one node, got %d", len(nodes))
	}
	if code, _ := do("DELETE", "/api/v1/nodes/"+enrolled.NodeID.String(), keyB, nil); code != http.StatusNotFound {
		t.Fatalf("deleting another tenant's node: %d", code)
	}

	// A network with members cannot be deleted; an empty one can.
	if code, _ := do("DELETE", "/api/v1/networks/"+netA, keyA, nil); code != http.StatusConflict {
		t.Fatalf("deleting a non-empty network: %d", code)
	}
	if code, _ := do("DELETE", "/api/v1/nodes/"+enrolled.NodeID.String(), keyA, nil); code != http.StatusNoContent {
		t.Fatalf("owner removing its node: %d", code)
	}
	if code, _ := do("DELETE", "/api/v1/networks/"+netA, keyA, nil); code != http.StatusNoContent {
		t.Fatalf("deleting an empty network: %d", code)
	}
	if code, _ := do("DELETE", "/api/v1/networks/"+netB, keyA, nil); code != http.StatusNotFound {
		t.Fatalf("deleting another tenant's network: %d", code)
	}

	// PoP removal is admin-only.
	_, _ = do("POST", "/api/v1/edge/register", "", nil) // (unauthenticated; ignored)
	_ = db.EdgePoPs.Create(context.Background(), &core.EdgePoP{ID: uuid.New(), PoPCode: "ZZ", Region: "r", PublicEndpoint: "1.1.1.1:1", PublicKey: kp.PublicKey})
	if code, _ := do("DELETE", "/api/v1/pops/ZZ", keyA, nil); code != http.StatusUnauthorized {
		t.Fatalf("tenant removing a PoP: %d", code)
	}
	if code, _ := do("DELETE", "/api/v1/pops/ZZ", "admin", nil); code != http.StatusNoContent {
		t.Fatalf("admin removing a PoP: %d", code)
	}
}

func TestAnonymousModeNeverActsAsARealTenant(t *testing.T) {
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	// require_auth is off (the default), but a real tenant already exists.
	srv := NewServer(&config.ControlPlaneConfig{SecretKey: "s", AdminAPIKey: "admin"}, db)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/tenants", strings.NewReader(`{"name":"acme","slug":"acme"}`))
	req.Header.Set("Authorization", "Bearer admin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("create tenant: %v", err)
	}
	resp.Body.Close()

	for _, path := range []string{"/api/v1/networks", "/api/v1/mesh/graph", "/api/v1/nodes?network_id=x"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("anonymous %s must be refused once real tenants exist, got %d", path, resp.StatusCode)
		}
	}
	if resp, _ := http.Get(ts.URL + "/api/v1/events"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous event stream must be refused, got %d", resp.StatusCode)
	}
}

func TestAPIContract(t *testing.T) {
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(&config.ControlPlaneConfig{SecretKey: "contract", AdminAPIKey: "admin", RequireAuth: true, DefaultCIDRv4: "100.64.0.0/16", DefaultCIDRv6: "fd00:cafe::/64"}, db)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	do := func(method, path, bearer string, body any) (*http.Response, []byte) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, ts.URL+path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("X-Request-ID", "req-123")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return resp, buf.Bytes()
	}
	tenant := func(slug string) string {
		_, body := do("POST", "/api/v1/tenants", "admin", map[string]string{"name": slug, "slug": slug})
		var tr tenantResponse
		_ = json.Unmarshal(body, &tr)
		return tr.APIKey
	}
	keyA, keyB := tenant("alpha"), tenant("beta")

	// Errors share one JSON envelope and echo the request ID.
	resp, body := do("GET", "/api/v1/networks", "wrong", nil)
	var e errorBody
	if err := json.Unmarshal(body, &e); err != nil || resp.StatusCode != 401 || e.Error.Code != "unauthorized" ||
		e.Error.Message == "" || e.Error.RequestID != "req-123" || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("error envelope: %d %s (%v)", resp.StatusCode, body, err)
	}

	// Lists are paginated with an opaque cursor, and walking them yields every item once.
	var ids []string
	for i := 0; i < 3; i++ {
		_, nb := do("POST", "/api/v1/networks", keyA, CreateNetworkRequest{Name: "n" + strconv.Itoa(i)})
		var n core.Network
		_ = json.Unmarshal(nb, &n)
		ids = append(ids, n.ID)
	}
	seen, cursor := map[string]bool{}, ""
	for pages := 0; pages < 5; pages++ {
		_, pb := do("GET", "/api/v1/networks?limit=2&cursor="+cursor, keyA, nil)
		var pg Page[core.Network]
		if err := json.Unmarshal(pb, &pg); err != nil || len(pg.Items) > 2 {
			t.Fatalf("page: %s (%v)", pb, err)
		}
		for _, n := range pg.Items {
			seen[n.ID] = true
		}
		if cursor = pg.NextCursor; cursor == "" {
			break
		}
	}
	if len(seen) != 3 {
		t.Fatalf("pagination lost or repeated items: %v", seen)
	}
	if resp, _ := do("GET", "/api/v1/networks?limit=0", keyA, nil); resp.StatusCode != 400 {
		t.Fatalf("limit=0: %d", resp.StatusCode)
	}
	if resp, _ := do("GET", "/api/v1/networks?cursor=!!", keyA, nil); resp.StatusCode != 400 {
		t.Fatalf("bad cursor: %d", resp.StatusCode)
	}

	// Get-by-ID is tenant-scoped: another tenant's resource looks missing.
	if resp, _ := do("GET", "/api/v1/networks/"+ids[0], keyA, nil); resp.StatusCode != 200 {
		t.Fatalf("owner get: %d", resp.StatusCode)
	}
	if resp, _ := do("GET", "/api/v1/networks/"+ids[0], keyB, nil); resp.StatusCode != 404 {
		t.Fatalf("cross-tenant get: %d", resp.StatusCode)
	}
	if resp, body := do("GET", "/api/v1/tenants/"+uuid.New().String(), "admin", nil); resp.StatusCode != 404 || bytes.Contains(body, []byte("zro_key_")) {
		t.Fatalf("missing tenant: %d %s", resp.StatusCode, body)
	}
}

func TestEdgeRegistrationAssignsStableMeshAddress(t *testing.T) {
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(&config.ControlPlaneConfig{SecretKey: "k", DefaultCIDRv4: "100.64.0.0/16", DefaultCIDRv6: "fd00:cafe::/64"}, db)
	register := func(code, key, cred string) (core.EdgePoP, string) {
		body, _ := json.Marshal(RegisterEdgePoPRequest{PoPCode: code, Region: "r", PublicEndpoint: "203.0.113.1:51820", PublicKey: key})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/v1/edge/register", bytes.NewReader(body))
		if cred != "" {
			req.Header.Set("Authorization", "Bearer "+cred)
		}
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("register %s: %s", code, rec.Body.String())
		}
		var out struct {
			core.EdgePoP
			PopKey string `json:"pop_key"`
		}
		_ = json.NewDecoder(rec.Body).Decode(&out)
		return out.EdgePoP, out.PopKey
	}
	kh, khKey := register("KH", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", "")
	sg, _ := register("SG", "AQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", "")
	if kh.OverlayIPv4 != "100.64.255.254" || sg.OverlayIPv4 != "100.64.255.253" || kh.OverlayIPv6 == "" {
		t.Fatalf("addresses: kh=%q sg=%q v6=%q", kh.OverlayIPv4, sg.OverlayIPv4, kh.OverlayIPv6)
	}
	if again, _ := register("KH", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", khKey); again.OverlayIPv4 != kh.OverlayIPv4 {
		t.Fatalf("address changed on re-register: %q", again.OverlayIPv4)
	}
}
