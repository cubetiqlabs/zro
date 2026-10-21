package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cubis/zro/pkg/config"
	"github.com/cubis/zro/pkg/control/events"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/crypto"
	"github.com/cubis/zro/pkg/store"
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
		PublicKey:      "kh-key=",
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
	var rules []core.ACLRule
	_ = json.NewDecoder(listAclRec.Body).Decode(&rules)
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
	var netsB []core.Network
	_ = json.NewDecoder(rListB.Body).Decode(&netsB)
	_ = rListB.Body.Close()

	if len(netsB) != 0 {
		t.Fatalf("Tenant Beta should see 0 networks, got %d", len(netsB))
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
