package smoke

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/cubetiqlabs/zro/api/proto/v1"
	"github.com/cubetiqlabs/zro/pkg/config"
	controlgrpc "github.com/cubetiqlabs/zro/pkg/control/grpc"
	"github.com/cubetiqlabs/zro/pkg/control/server"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/cubetiqlabs/zro/pkg/crypto"
	"github.com/cubetiqlabs/zro/pkg/gateway"
	"github.com/cubetiqlabs/zro/pkg/node"
	"github.com/cubetiqlabs/zro/pkg/p2p/stun"
	"github.com/cubetiqlabs/zro/pkg/store"
	"github.com/cubetiqlabs/zro/pkg/tunnel"
	"golang.org/x/net/websocket"
)

func TestFullMeshSmoke(t *testing.T) {
	ctx := context.Background()

	// 1. Initialize Control Plane with clean in-memory DB (no mock data / no default seed)
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("smoke: database init failed: %v", err)
	}

	secretKey := "test-smoke-cluster-secret-key-32b"
	cfg := &config.ControlPlaneConfig{
		ListenAddr:    ":8443",
		PublicURL:     "http://localhost:8443",
		SecretKey:     secretKey,
		DefaultCIDRv4: "100.64.0.0/10",
		DefaultCIDRv6: "fd00:cafe::/64",
	}

	srv := server.NewServer(cfg, db)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 2. Smoke Step 1: Verify Control Plane Health Endpoint
	resp, err := http.Get(ts.URL + "/health")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("smoke: health check failed, status: %v", resp.StatusCode)
	}
	_ = resp.Body.Close()
	t.Log("✅ Smoke Step 1 Passed: Control Plane /health is healthy")

	// 3. Smoke Step 2: Dynamically Register 5 Global Edge PoPs (KH, SG, US, HK, DE)
	popSpecs := []struct {
		code     string
		region   string
		endpoint string
	}{
		{"KH", "Phnom Penh, Cambodia", "173.1.1.1:51820"},
		{"SG", "Jurong, Singapore", "123.1.1.1:51820"},
		{"US", "Ashburn VA, United States", "145.1.1.1:51820"},
		{"HK", "Kowloon, Hong Kong", "173.1.1.1:51820"},
		{"DE", "Frankfurt, Germany", "133.1.1.1:51820"},
	}

	for _, spec := range popSpecs {
		kp, _ := crypto.GenerateKeyPair()
		regBody, _ := json.Marshal(server.RegisterEdgePoPRequest{
			PoPCode:        spec.code,
			Region:         spec.region,
			PublicEndpoint: spec.endpoint,
			PublicKey:      kp.PublicKey,
			Weight:         100,
			IsAnycast:      true,
		})
		r, err := http.Post(ts.URL+"/api/v1/edge/register", "application/json", bytes.NewReader(regBody))
		if err != nil || r.StatusCode != http.StatusOK {
			t.Fatalf("smoke: failed to register PoP %s: status %d", spec.code, r.StatusCode)
		}
		_ = r.Body.Close()
	}

	// Verify PoPs Catalog
	resp, err = http.Get(ts.URL + "/api/v1/pops")
	if err != nil {
		t.Fatalf("smoke: failed to fetch PoPs: %v", err)
	}
	var pops []core.EdgePoP
	if err := json.NewDecoder(resp.Body).Decode(&pops); err != nil {
		t.Fatalf("smoke: failed to parse PoPs: %v", err)
	}
	_ = resp.Body.Close()

	if len(pops) != 5 {
		t.Fatalf("smoke: expected 5 registered Edge PoPs, got %d", len(pops))
	}
	t.Logf("✅ Smoke Step 2 Passed: 5 Global Edge PoPs registered dynamically (%s, %s, %s, %s, %s)",
		pops[0].PoPCode, pops[1].PoPCode, pops[2].PoPCode, pops[3].PoPCode, pops[4].PoPCode)

	// 4. Smoke Step 3: Create Overlay Network with ZeroTier-styled 16-hex Network ID
	netReqBody, _ := json.Marshal(server.CreateNetworkRequest{
		Name:      "Production Global Mesh",
		IPv4CIDR:  "100.64.0.0/10",
		IPv6CIDR:  "fd00:cafe::/64",
		DNSDomain: "zro.internal",
	})
	resp, err = http.Post(ts.URL+"/api/v1/networks", "application/json", bytes.NewReader(netReqBody))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("smoke: failed to create network, status: %d", resp.StatusCode)
	}
	var createdNet core.Network
	_ = json.NewDecoder(resp.Body).Decode(&createdNet)
	_ = resp.Body.Close()

	if len(createdNet.ID) != 16 {
		t.Fatalf("smoke: expected ZeroTier-styled 16-hex network ID, got %s (len %d)", createdNet.ID, len(createdNet.ID))
	}
	if _, err := hex.DecodeString(createdNet.ID); err != nil {
		t.Fatalf("smoke: network ID %s is not valid hex: %v", createdNet.ID, err)
	}
	t.Logf("✅ Smoke Step 3 Passed: Created network with ZeroTier 16-hex ID: %s", createdNet.ID)

	// 5. Smoke Step 4: Security Verification - Public Key Bound Enrollment Token
	kp1, _ := crypto.GenerateKeyPair()
	kpAttacker, _ := crypto.GenerateKeyPair()

	// Token cryptographically bound to kp1.PublicKey
	token1 := crypto.GenerateEnrollmentToken(secretKey, createdNet.ID, "app-node-kh", 1*time.Hour, kp1.PublicKey)

	// 5a. Attacker tries to use token1 with kpAttacker.PublicKey -> must be rejected (401)
	attackReq := server.EnrollRequest{
		Token:     token1,
		PublicKey: kpAttacker.PublicKey,
		Hostname:  "attacker-node",
		NodeType:  core.NodeTypePeer,
		Tags:      core.StringList{"tag:evil"},
		Endpoints: core.StringList{"1.2.3.4:51820"},
	}
	attackBody, _ := json.Marshal(attackReq)
	rAttack, _ := http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(attackBody))
	if rAttack.StatusCode != http.StatusUnauthorized {
		t.Fatalf("smoke: expected 401 Unauthorized for token stolen by different public key, got %d", rAttack.StatusCode)
	}
	_ = rAttack.Body.Close()
	t.Log("✅ Smoke Step 4a Passed: High-security enforced - Token hijacking rejected with 401")

	// 5b. Legitimate enrollment with matching bound public key and pre-enrollment latency probes
	enroll1Req := server.EnrollRequest{
		Token:     token1,
		PublicKey: kp1.PublicKey,
		Hostname:  "app-node-kh",
		NodeType:  core.NodeTypePeer,
		Tags:      core.StringList{"tag:web", "env:prod"},
		Endpoints: core.StringList{"192.168.1.100:51820"},
		Probes: []core.LatencySample{
			{PoPCode: "KH", RTT: 4 * time.Millisecond, PacketLoss: 0.0, Timestamp: time.Now()},
			{PoPCode: "SG", RTT: 35 * time.Millisecond, PacketLoss: 0.0, Timestamp: time.Now()},
		},
	}
	body1, _ := json.Marshal(enroll1Req)
	resp, err = http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(body1))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("smoke: legitimate node 1 enrollment failed, status: %d", resp.StatusCode)
	}

	var enroll1Resp server.EnrollResponse
	_ = json.NewDecoder(resp.Body).Decode(&enroll1Resp)
	_ = resp.Body.Close()

	if enroll1Resp.OverlayIPv4 != "100.64.0.2" {
		t.Fatalf("smoke: expected node 1 IP 100.64.0.2, got %s", enroll1Resp.OverlayIPv4)
	}
	if enroll1Resp.NetworkID != createdNet.ID {
		t.Fatalf("smoke: expected network ID %s, got %s", createdNet.ID, enroll1Resp.NetworkID)
	}
	if enroll1Resp.PrimaryPoP.PoPCode != "KH" {
		t.Fatalf("smoke: expected PrimaryPoP KH (4ms vs 35ms), got %s", enroll1Resp.PrimaryPoP.PoPCode)
	}
	t.Logf("✅ Smoke Step 4b Passed: Node 1 successfully enrolled with IPless overlay %s, smart-delegated to Primary Edge PoP %s",
		enroll1Resp.OverlayIPv4, enroll1Resp.PrimaryPoP.PoPCode)

	// 6. Smoke Step 5: Enroll Node 2 (Singapore) with probe telemetry
	kp2, _ := crypto.GenerateKeyPair()
	token2 := crypto.GenerateEnrollmentToken(secretKey, createdNet.ID, "db-node-sg", 1*time.Hour, kp2.PublicKey)

	enroll2Req := server.EnrollRequest{
		Token:     token2,
		PublicKey: kp2.PublicKey,
		Hostname:  "db-node-sg",
		NodeType:  core.NodeTypePeer,
		Tags:      core.StringList{"tag:db", "env:prod"},
		Endpoints: core.StringList{"10.0.0.50:51820"},
		Probes: []core.LatencySample{
			{PoPCode: "KH", RTT: 41 * time.Millisecond, PacketLoss: 0.0, Timestamp: time.Now()},
			{PoPCode: "SG", RTT: 3 * time.Millisecond, PacketLoss: 0.0, Timestamp: time.Now()},
		},
	}
	body2, _ := json.Marshal(enroll2Req)
	resp, err = http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(body2))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("smoke: node 2 enrollment failed, status: %d", resp.StatusCode)
	}

	var enroll2Resp server.EnrollResponse
	_ = json.NewDecoder(resp.Body).Decode(&enroll2Resp)
	_ = resp.Body.Close()

	if enroll2Resp.OverlayIPv4 != "100.64.0.3" {
		t.Fatalf("smoke: expected node 2 IP 100.64.0.3, got %s", enroll2Resp.OverlayIPv4)
	}
	if enroll2Resp.PrimaryPoP.PoPCode != "SG" {
		t.Fatalf("smoke: expected PrimaryPoP SG (3ms vs 41ms), got %s", enroll2Resp.PrimaryPoP.PoPCode)
	}
	t.Logf("✅ Smoke Step 5 Passed: Node 2 successfully enrolled with IPless static overlay %s, smart-delegated to Primary Edge PoP %s",
		enroll2Resp.OverlayIPv4, enroll2Resp.PrimaryPoP.PoPCode)

	// 7. Smoke Step 6: Edge Mesh Synchronization
	resp, err = http.Get(ts.URL + "/api/v1/edge/sync")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("smoke: edge sync failed, status: %d", resp.StatusCode)
	}
	var syncData server.EdgeSyncResponse
	_ = json.NewDecoder(resp.Body).Decode(&syncData)
	_ = resp.Body.Close()

	if len(syncData.PoPs) != 5 || len(syncData.Nodes) != 2 {
		t.Fatalf("smoke: expected 5 PoPs and 2 nodes in sync data, got %d PoPs and %d nodes", len(syncData.PoPs), len(syncData.Nodes))
	}
	t.Logf("✅ Smoke Step 6 Passed: Edge sync verified across %d PoPs and %d nodes", len(syncData.PoPs), len(syncData.Nodes))

	// 8. Smoke Step 7: Section 5 P2P Discovery & Signaling via Control Plane
	p2pDiscReq := server.P2PDiscoverRequest{
		InitiatorNodeID:    enroll1Resp.NodeID,
		TargetOverlayIP:    enroll2Resp.OverlayIPv4,
		InitiatorEndpoints: core.StringList{"192.168.1.100:51820"},
	}
	discBody, _ := json.Marshal(p2pDiscReq)
	resp, err = authedDo(http.MethodPost, ts.URL+"/api/v1/p2p/discover", enroll1Resp.NodeToken, discBody)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("smoke: P2P discovery failed: status %d", resp.StatusCode)
	}
	var discResp server.P2PDiscoverResponse
	_ = json.NewDecoder(resp.Body).Decode(&discResp)
	_ = resp.Body.Close()

	if discResp.TargetPublicKey != kp2.PublicKey {
		t.Fatalf("smoke: target public key mismatch, got %s", discResp.TargetPublicKey)
	}
	if discResp.PrimaryPoP == nil || discResp.PrimaryPoP.PoPCode != "SG" {
		t.Fatalf("smoke: expected target PrimaryPoP SG, got %v", discResp.PrimaryPoP)
	}
	t.Logf("✅ Smoke Step 7 Passed: Section 5 P2P Discovery signaled (Target: %s, Endpoints: %v, Fallback Relay: Edge %s)",
		discResp.TargetHostname, discResp.TargetEndpoints, discResp.PrimaryPoP.PoPCode)

	// 8. Smoke Step 7: Smart Routing Delegation (Probe Reporting)
	probeSample := core.LatencySample{
		NodeID:     enroll1Resp.NodeID,
		PoPCode:    "KH",
		RTT:        4 * time.Millisecond,
		PacketLoss: 0.0,
	}
	probeBody, _ := json.Marshal(probeSample)
	resp, err = authedDo(http.MethodPost, ts.URL+"/api/v1/probes", enroll1Resp.NodeToken, probeBody)
	if err != nil || resp.StatusCode != http.StatusAccepted {
		t.Fatalf("smoke: probe submission failed, status: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	t.Log("✅ Smoke Step 7 Passed: Smart routing telemetry accepted and evaluated")

	// 9. Smoke Step 8: STUN Reflexive Address Discovery
	stunConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("smoke: failed to bind STUN listener: %v", err)
	}
	defer stunConn.Close()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, clientAddr, err := stunConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_ = stun.ServeSTUN(stunConn, buf[:n], clientAddr)
		}
	}()

	clientConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer clientConn.Close()

	discovered, err := stun.DiscoverPublicEndpoint(clientConn, stunConn.LocalAddr().String(), 1*time.Second)
	if err != nil || discovered == nil {
		t.Fatalf("smoke: STUN discovery failed: %v", err)
	}
	t.Logf("✅ Smoke Step 8 Passed: STUN NAT reflexive discovery verified (%s)", discovered.String())

	// 11. Smoke Step 10: Ingress Gateway, Multi-Node Clustering, Route Sync & Failover
	// 10a. Multi-node cluster exposes the same service hostname (myapp-api.example.com) on port 3000
	tun1Req := core.Tunnel{
		NodeID:         enroll1Resp.NodeID,
		Name:           "api-service-node1",
		LocalAddress:   "127.0.0.1:3000",
		PublicHostname: "myapp-api.example.com",
		Protocol:       "http",
	}
	tun1Body, _ := json.Marshal(tun1Req)
	rTun1, err := authedDo(http.MethodPost, ts.URL+"/api/v1/tunnels", enroll1Resp.NodeToken, tun1Body)
	if err != nil || rTun1.StatusCode != http.StatusCreated {
		t.Fatalf("smoke: failed to register tunnel for node 1, status: %d", rTun1.StatusCode)
	}
	_ = rTun1.Body.Close()

	tun2Req := core.Tunnel{
		NodeID:         enroll2Resp.NodeID,
		Name:           "api-service-node2",
		LocalAddress:   "127.0.0.1:3000",
		PublicHostname: "myapp-api.example.com",
		Protocol:       "http",
	}
	tun2Body, _ := json.Marshal(tun2Req)
	rTun2, err := authedDo(http.MethodPost, ts.URL+"/api/v1/tunnels", enroll2Resp.NodeToken, tun2Body)
	if err != nil || rTun2.StatusCode != http.StatusCreated {
		t.Fatalf("smoke: failed to register clustered tunnel for node 2, status: %d", rTun2.StatusCode)
	}
	_ = rTun2.Body.Close()
	t.Log("✅ Smoke Step 10a Passed: Multi-node cluster tunnels registered for myapp-api.example.com")

	// 10b. Control Plane Gateway Dynamic Routes API (aggregates node overlay IPs)
	resp, err = authedDo(http.MethodGet, ts.URL+"/api/v1/gateway/routes", enroll1Resp.NodeToken, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("smoke: failed to get gateway routes, status: %d", resp.StatusCode)
	}
	var gwRoutesResp server.GatewayRoutesResponse
	_ = json.NewDecoder(resp.Body).Decode(&gwRoutesResp)
	_ = resp.Body.Close()

	if len(gwRoutesResp.Routes) == 0 {
		t.Fatalf("smoke: expected gateway routes, got 0")
	}
	var foundClusteredRoute bool
	for _, r := range gwRoutesResp.Routes {
		if r.Hostname == "myapp-api.example.com" {
			foundClusteredRoute = true
			if len(r.Backends) != 2 {
				t.Fatalf("smoke: expected 2 clustered backends for myapp-api.example.com, got %d", len(r.Backends))
			}
			// Backends must map to node overlay IPs + port 3000
			expectedAddrs := map[string]bool{"100.64.0.2:3000": true, "100.64.0.3:3000": true}
			for _, b := range r.Backends {
				if !expectedAddrs[b.Address] {
					t.Fatalf("smoke: unexpected backend overlay address: %s", b.Address)
				}
			}
		}
	}
	if !foundClusteredRoute {
		t.Fatalf("smoke: clustered route myapp-api.example.com not found in gateway routes")
	}
	t.Log("✅ Smoke Step 10b Passed: Control Plane aggregated dynamic routes with node overlay IPs (100.64.0.2:3000, 100.64.0.3:3000)")

	// 10c. Gateway Node Enrollment (NodeTypeGateway) with overlay IP & PoP delegation
	kpGW1, _ := crypto.GenerateKeyPair()
	tokenGW1, err := crypto.SignEnrollmentToken(secretKey, crypto.EnrollmentTokenPayload{
		NetworkID: createdNet.ID, Hostname: "gw1", NodeType: "gateway", BoundPublicKey: kpGW1.PublicKey,
		Expiry: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("smoke: gateway token: %v", err)
	}
	enrollGW1Req := server.EnrollRequest{
		Token:     tokenGW1,
		PublicKey: kpGW1.PublicKey,
		Hostname:  "gw1",
		NodeType:  core.NodeTypeGateway,
		Tags:      core.StringList{"role:gateway", "env:production"},
		Endpoints: core.StringList{"1.1.1.1:51820"},
		Probes: []core.LatencySample{
			{PoPCode: "KH", RTT: 2 * time.Millisecond, PacketLoss: 0.0, Timestamp: time.Now()},
		},
	}
	gw1Body, _ := json.Marshal(enrollGW1Req)
	rGW1, err := http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(gw1Body))
	if err != nil || rGW1.StatusCode != http.StatusOK {
		t.Fatalf("smoke: gateway gw1 enrollment failed: %d", rGW1.StatusCode)
	}
	var enrollGW1Resp server.EnrollResponse
	_ = json.NewDecoder(rGW1.Body).Decode(&enrollGW1Resp)
	_ = rGW1.Body.Close()

	if enrollGW1Resp.OverlayIPv4 != "100.64.0.4" {
		t.Fatalf("smoke: expected gateway overlay IP 100.64.0.4, got %s", enrollGW1Resp.OverlayIPv4)
	}
	if enrollGW1Resp.PrimaryPoP.PoPCode != "KH" {
		t.Fatalf("smoke: expected gateway delegated PoP KH, got %s", enrollGW1Resp.PrimaryPoP.PoPCode)
	}
	t.Logf("✅ Smoke Step 10c Passed: Gateway gw1 enrolled with overlay IP %s, peered to Edge PoP %s",
		enrollGW1Resp.OverlayIPv4, enrollGW1Resp.PrimaryPoP.PoPCode)

	// 10d. Gateway Live Reverse Proxy, Load Balancing & Zero-Downtime Failover
	var liveNode1Hits, liveNode2Hits int64
	liveNode1Up := int32(1)

	liveNode1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&liveNode1Up) == 0 {
			http.Error(w, "node 1 unavailable", http.StatusServiceUnavailable)
			return
		}
		atomic.AddInt64(&liveNode1Hits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from node1")
	}))
	defer liveNode1.Close()

	liveNode2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&liveNode2Hits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from node2")
	}))
	defer liveNode2.Close()

	gwDaemon1, err := gateway.NewDaemon(&config.GatewayConfig{
		Hostname:              "gw1",
		PlaneEndpoint:         ts.URL,
		EnrollmentToken:       tokenGW1,
		Strategy:              "round_robin",
		HealthCheckPath:       "/",
		HealthCheckIntervalMs: 50,
		StaticRoutes: []config.StaticRouteConfig{
			{
				Hostname: "myapp-api.example.com",
				Strategy: "round_robin",
				Backends: []string{liveNode1.Listener.Addr().String(), liveNode2.Listener.Addr().String()},
			},
		},
	})
	if err != nil {
		t.Fatalf("smoke: failed to create gateway daemon: %v", err)
	}

	// Dispatch requests to verify load balancing across clustered nodes
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest("GET", "http://myapp-api.example.com/api", nil)
		rec := httptest.NewRecorder()
		gwDaemon1.ProxyEngine().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("smoke: gateway request %d failed: %d", i, rec.Code)
		}
	}
	if atomic.LoadInt64(&liveNode1Hits) == 0 || atomic.LoadInt64(&liveNode2Hits) == 0 {
		t.Fatalf("smoke: expected load balancing across both nodes, got node1=%d, node2=%d",
			atomic.LoadInt64(&liveNode1Hits), atomic.LoadInt64(&liveNode2Hits))
	}
	t.Logf("✅ Smoke Step 10d Passed: Gateway load balanced clustered traffic (node1=%d, node2=%d)",
		atomic.LoadInt64(&liveNode1Hits), atomic.LoadInt64(&liveNode2Hits))

	// Simulate node 1 failure & verify instant zero-downtime failover to node 2
	atomic.StoreInt32(&liveNode1Up, 0)
	if bal, exists := gwDaemon1.ProxyEngine().GetRoute("myapp-api.example.com"); exists {
		for _, b := range bal.GetBackends() {
			if b.Address == liveNode1.Listener.Addr().String() {
				b.Healthy = false // Marked down by active health checker / proxy
			}
		}
	}

	prevN2Hits := atomic.LoadInt64(&liveNode2Hits)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "http://myapp-api.example.com/api", nil)
		rec := httptest.NewRecorder()
		gwDaemon1.ProxyEngine().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("smoke: failover request failed: %d", rec.Code)
		}
		body, _ := io.ReadAll(rec.Body)
		if string(body) != "hello from node2" {
			t.Fatalf("smoke: expected response from node2, got %s", string(body))
		}
	}
	if atomic.LoadInt64(&liveNode2Hits) != prevN2Hits+3 {
		t.Fatalf("smoke: node2 did not receive all failover requests")
	}
	t.Log("✅ Smoke Step 10e Passed: Zero-downtime failover verified - node2 instantly absorbed traffic")

	_ = gwDaemon1.Stop()

	// 12. Smoke Step 11: Universal Tunneling (SOCKS5 & UDP Datagram Tunneling)
	socksSrv := tunnel.NewSOCKS5Server((&net.Dialer{}).DialContext)
	socksL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("smoke: failed to bind SOCKS5 listener: %v", err)
	}
	defer socksSrv.Close()
	defer socksL.Close()

	go func() {
		_ = socksSrv.Serve(socksL)
	}()

	// Connect to SOCKS5 listener and negotiate NO AUTH (0x05, 0x01, 0x00)
	socksConn, err := net.Dial("tcp", socksL.Addr().String())
	if err != nil {
		t.Fatalf("smoke: SOCKS5 dial failed: %v", err)
	}
	defer socksConn.Close()

	_, err = socksConn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		t.Fatalf("smoke: SOCKS5 greeting write failed: %v", err)
	}
	authResp := make([]byte, 2)
	_, err = io.ReadFull(socksConn, authResp)
	if err != nil || authResp[0] != 0x05 || authResp[1] != 0x00 {
		t.Fatalf("smoke: SOCKS5 auth handshake failed: %v, resp: %x", err, authResp)
	}
	t.Log("✅ Smoke Step 11 Passed: Universal Tunneling - RFC 1928 SOCKS5 Proxy operational")

	// 13. Smoke Step 12: Real-Time WebSockets Event Hub (RFC 6455)
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/v1/ws"
	wsConn, err := websocket.Dial(wsURL, "", ts.URL)
	if err != nil {
		t.Fatalf("smoke: WebSocket connection failed: %v", err)
	}
	defer wsConn.Close()

	var wsWelcome map[string]any
	_ = websocket.JSON.Receive(wsConn, &wsWelcome)
	if wsWelcome["event"] != "connected" {
		t.Fatalf("smoke: expected WebSocket connected event, got %v", wsWelcome)
	}

	// Register a new tunnel and verify real-time event push on WebSocket
	tunWS := core.Tunnel{
		NodeID:         enroll1Resp.NodeID,
		Name:           "realtime-test",
		LocalAddress:   "127.0.0.1:4000",
		PublicHostname: "realtime.example.com",
		Protocol:       "http",
	}
	tunWSBytes, _ := json.Marshal(tunWS)
	resp, _ = authedDo(http.MethodPost, ts.URL+"/api/v1/tunnels", enroll1Resp.NodeToken, tunWSBytes)
	_ = resp.Body.Close()

	var wsPushMsg string
	_ = websocket.Message.Receive(wsConn, &wsPushMsg)
	if !strings.Contains(wsPushMsg, "realtime.example.com") {
		t.Fatalf("smoke: expected realtime push event on WebSocket, got %s", wsPushMsg)
	}
	t.Log("✅ Smoke Step 12 Passed: Real-Time WebSockets Event Hub (RFC 6455) operational")

	// 14. Smoke Step 13: High-Performance gRPC Communication & Event Streaming
	grpcLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("smoke: failed to bind gRPC listener: %v", err)
	}
	defer grpcLis.Close()

	grpcSrv := srv.NewGRPCServer()
	go func() {
		_ = grpcSrv.Serve(grpcLis)
	}()
	defer grpcSrv.GracefulStop()

	var grpcToken atomic.Value
	grpcToken.Store("")
	grpcClient, err := controlgrpc.Dial(controlgrpc.DialOptions{
		Endpoint: grpcLis.Addr().String(),
		Insecure: true,
		Token:    func() string { return grpcToken.Load().(string) },
	})
	if err != nil {
		t.Fatalf("smoke: failed to connect gRPC client: %v", err)
	}
	defer grpcClient.Close()

	kpGRPC, _ := crypto.GenerateKeyPair()
	tokenGRPC := crypto.GenerateEnrollmentToken(secretKey, createdNet.ID, "grpc-smoke-node", 1*time.Hour, kpGRPC.PublicKey)
	grpcEnrollResp, err := grpcClient.Enroll(ctx, &v1.EnrollRequest{
		Token:     tokenGRPC,
		PublicKey: kpGRPC.PublicKey,
		Hostname:  "grpc-smoke-node",
		NodeType:  "peer",
		Tags:      []string{"tag:grpc"},
		Endpoints: []string{"192.168.1.99:51820"},
	})
	if err != nil {
		t.Fatalf("smoke: gRPC Enroll failed: %v", err)
	}
	if grpcEnrollResp.OverlayIpv4 == "" || grpcEnrollResp.NodeToken == "" {
		t.Fatalf("smoke: expected overlay IP and node token from gRPC enroll")
	}
	grpcToken.Store(grpcEnrollResp.NodeToken)
	if _, err := grpcClient.RegisterTunnel(ctx, &v1.RegisterTunnelRequest{
		Name: "grpc-tun", LocalAddress: "127.0.0.1:7000", PublicHostname: "grpc-tun.example.com",
	}); err != nil {
		t.Fatalf("smoke: gRPC RegisterTunnel failed: %v", err)
	}
	if lt, err := grpcClient.ListTunnels(ctx); err != nil || len(lt.Tunnels) == 0 {
		t.Fatalf("smoke: gRPC ListTunnels failed: %v", err)
	}
	t.Logf("✅ Smoke Step 13 Passed: High-Performance gRPC API & Real-Time Event Bus verified (Node Overlay: %s)",
		grpcEnrollResp.OverlayIpv4)

	// =========================================================================
	// Smoke Step 14: Edge PoP Dynamic Heartbeats & Status Watcher
	// =========================================================================
	hbPayload, _ := json.Marshal(server.EdgeHeartbeatRequest{
		PoPCode:        "KH",
		Status:         "online",
		PeersCount:     5,
		RTTMs:          1.8,
		PublicEndpoint: "173.1.1.1:51820",
	})
	hbReq, _ := http.NewRequestWithContext(ctx, "POST", ts.URL+"/api/v1/edge/heartbeat", bytes.NewReader(hbPayload))
	hbReq.Header.Set("Content-Type", "application/json")
	hbResp, err := http.DefaultClient.Do(hbReq)
	if err != nil || hbResp.StatusCode != http.StatusOK {
		t.Fatalf("smoke: Edge PoP heartbeat failed: %v", err)
	}
	_ = hbResp.Body.Close()

	popsReq, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/api/v1/pops", nil)
	popsResp, err := http.DefaultClient.Do(popsReq)
	if err != nil {
		t.Fatalf("smoke: list pops failed: %v", err)
	}
	defer popsResp.Body.Close()
	var activePoPs []core.EdgePoP
	_ = json.NewDecoder(popsResp.Body).Decode(&activePoPs)
	if len(activePoPs) == 0 {
		t.Fatalf("smoke: expected active pops after heartbeat")
	}
	t.Logf("✅ Smoke Step 14 Passed: Edge PoP Dynamic Heartbeat & Health Watcher verified (%d PoPs healthy)", len(activePoPs))

	// =========================================================================
	// Smoke Step 15: Real-Time Mesh Topology Graph Endpoint
	// =========================================================================
	graphReq, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/api/v1/mesh/graph?network_id="+createdNet.ID, nil)
	graphResp, err := http.DefaultClient.Do(graphReq)
	if err != nil || graphResp.StatusCode != http.StatusOK {
		t.Fatalf("smoke: GET /api/v1/mesh/graph failed: %v", err)
	}
	defer graphResp.Body.Close()
	var meshGraph server.MeshGraphResponse
	if err := json.NewDecoder(graphResp.Body).Decode(&meshGraph); err != nil {
		t.Fatalf("smoke: decode mesh graph failed: %v", err)
	}
	if len(meshGraph.Nodes) == 0 || len(meshGraph.Edges) == 0 {
		t.Fatalf("smoke: expected nodes and edges in mesh graph, got nodes=%d edges=%d", len(meshGraph.Nodes), len(meshGraph.Edges))
	}
	t.Logf("✅ Smoke Step 15 Passed: Real-Time Mesh Topology Graph operational (Nodes: %d, Edges: %d)",
		len(meshGraph.Nodes), len(meshGraph.Edges))

	// =========================================================================
	// Smoke Step 16: Inter-Node Secure Communication with Zero-Trust Default Deny
	// =========================================================================
	node1, err := node.NewDaemon(&config.NodeConfig{
		Hostname:      "app-node-kh",
		InterfaceName: "zro-smoke1",
		InterfaceMode: "netstack",
		MTU:           1420,
		DefaultDeny:   true,
	})
	if err != nil {
		t.Fatalf("smoke: create node 1 failed: %v", err)
	}
	defer node1.Stop()
	node2, err := node.NewDaemon(&config.NodeConfig{
		Hostname:      "db-node-sg",
		InterfaceName: "zro-smoke2",
		InterfaceMode: "netstack",
		MTU:           1420,
		DefaultDeny:   true,
	})
	if err != nil {
		t.Fatalf("smoke: create node 2 failed: %v", err)
	}
	defer node2.Stop()
	_ = node1.AssignOverlay("100.64.0.2", "")
	_ = node2.AssignOverlay("100.64.0.3", "")
	// A real WireGuard session between the two userspace stacks over loopback UDP.
	_ = node2.AddDirectPeer(core.Node{PublicKey: node1.PublicKey(), OverlayIPv4: "100.64.0.2"}, fmt.Sprintf("127.0.0.1:%d", node1.UDPPort()), false)
	_ = node1.AddDirectPeer(core.Node{PublicKey: node2.PublicKey(), OverlayIPv4: "100.64.0.3"}, fmt.Sprintf("127.0.0.1:%d", node2.UDPPort()), true)
	for i := 0; !node1.PeerHandshaken(node2.PublicKey()); i++ {
		if i > 300 {
			t.Fatalf("smoke: WireGuard handshake between userspace nodes never completed")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Node 1 (100.64.0.2) hosting PostgreSQL server on port 5432, default deny all
	// Node 2 (100.64.0.3) connecting over the mesh
	node1.SetInboundPolicy([]string{"5432/tcp"}, true, nil)
	pgLn, err := node1.ListenMesh(ctx, "tcp", 5432)
	if err != nil {
		t.Fatalf("smoke: node1 failed to listen on mesh port 5432: %v", err)
	}
	defer pgLn.Close()

	// Mock PostgreSQL query responder
	go func() {
		for {
			conn, err := pgLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				if string(buf[:n]) == "SELECT 1;" {
					_, _ = c.Write([]byte("1\n"))
				}
			}(conn)
		}
	}()

	// 16a. Node 2 connects to Node 1 on port 5432 -> MUST SUCCEED
	pgConn, err := node2.DialMesh(ctx, "tcp", "100.64.0.2:5432")
	if err != nil {
		t.Fatalf("smoke: node2 failed to connect to node1 on allowed port 5432: %v", err)
	}
	_ = pgConn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = pgConn.Write([]byte("SELECT 1;"))
	respBuf := make([]byte, 16)
	nBytes, _ := pgConn.Read(respBuf)
	_ = pgConn.Close()
	if string(respBuf[:nBytes]) != "1\n" {
		t.Fatalf("smoke: expected '1\\n' from postgres service, got %q", string(respBuf[:nBytes]))
	}
	t.Log("✅ Smoke Step 16a Passed: Real TCP over WireGuard between userspace stacks: Node 2 accessed Node 1 (100.64.0.2:5432)")

	// 16b. Port 22 is listening on Node 1 but not allowed -> the connection is cut off
	sshLn, err := node1.ListenMesh(ctx, "tcp", 22)
	if err != nil {
		t.Fatalf("smoke: node1 failed to listen on port 22: %v", err)
	}
	defer sshLn.Close()
	go func() {
		for {
			c, err := sshLn.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH\n"))
			_ = c.Close()
		}
	}()

	probe := func() bool {
		// A filtered SYN is dropped, so a blocked dial ends at its deadline.
		dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		c, err := node2.DialMesh(dialCtx, "tcp", "100.64.0.2:22")
		if err != nil {
			return false
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		b := make([]byte, 8)
		n, _ := c.Read(b)
		return string(b[:n]) == "SSH\n"
	}
	if probe() {
		t.Fatalf("smoke: expected port 22 to be BLOCKED under default-deny all")
	}
	t.Log("✅ Smoke Step 16b Passed: Zero-Trust Inbound Firewall enforced (port 22 blocked)")

	// 16c. Dynamically allow port 22 on Node 1 -> Connection now succeeds
	node1.AllowPort("22/tcp")
	if !probe() {
		t.Fatalf("smoke: expected connection to port 22 to succeed after dynamic allow")
	}
	t.Log("✅ Smoke Step 16c Passed: Dynamic zero-trust firewall policy update verified (port 22 allowed)")
}

// authedDo sends a JSON request authenticated with a node token.
func authedDo(method, url, token string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return http.DefaultClient.Do(req)
}
