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
	"testing"
	"time"

	"github.com/cubis/zro/pkg/config"
	"github.com/cubis/zro/pkg/control/server"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/crypto"
	"github.com/cubis/zro/pkg/gateway/balancer"
	"github.com/cubis/zro/pkg/gateway/proxy"
	"github.com/cubis/zro/pkg/p2p/puncher"
	"github.com/cubis/zro/pkg/p2p/stun"
	"github.com/cubis/zro/pkg/store"
	"github.com/cubis/zro/pkg/tunnel"
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
	resp, err = http.Post(ts.URL+"/api/v1/p2p/discover", "application/json", bytes.NewReader(discBody))
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
	resp, err = http.Post(ts.URL+"/api/v1/probes", "application/json", bytes.NewReader(probeBody))
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

	// 10. Smoke Step 9: P2P Hole Punching Simulation
	p2pConn1, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer p2pConn1.Close()
	p2pConn2, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer p2pConn2.Close()

	go func() {
		buf := make([]byte, 256)
		for {
			n, remote, err := p2pConn2.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if bytes.Equal(buf[:n], puncher.MagicPing) {
				_, _ = p2pConn2.WriteToUDP(puncher.MagicPong, remote)
			}
		}
	}()

	p2pResult, err := puncher.Punch(ctx, p2pConn1, p2pConn2.LocalAddr().String(), 500*time.Millisecond)
	if err != nil || !p2pResult.Success {
		t.Fatalf("smoke: P2P punch failed: %v", err)
	}
	t.Logf("✅ Smoke Step 9 Passed: Direct P2P Hole Punch established (RTT: %v)", p2pResult.RTT)

	// 11. Smoke Step 10: Ingress Gateway Reverse Proxy & Load Balancer
	backendMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "Hello from private mesh backend!")
	}))
	defer backendMock.Close()

	gwEngine := proxy.NewEngine()
	backends := []*balancer.Backend{
		{Address: backendMock.Listener.Addr().String(), Healthy: true, Weight: 100},
	}
	bal := balancer.NewBalancer(balancer.StrategyLatency, backends)
	gwEngine.RegisterRoute("app.cubis.internal", bal)

	gwReq := httptest.NewRequest("GET", "http://app.cubis.internal/test", nil)
	gwRec := httptest.NewRecorder()
	gwEngine.ServeHTTP(gwRec, gwReq)

	gwBody, _ := io.ReadAll(gwRec.Body)
	if gwRec.Code != http.StatusOK || string(gwBody) != "Hello from private mesh backend!" {
		t.Fatalf("smoke: Gateway reverse proxy failed: %d, body: %s", gwRec.Code, string(gwBody))
	}
	t.Log("✅ Smoke Step 10 Passed: Cloud-Native Gateway Reverse Proxy & Load Balancer verified")

	// 12. Smoke Step 11: Universal Tunneling (SOCKS5 & UDP Datagram Tunneling)
	socksSrv := tunnel.NewSOCKS5Server(nil)
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
}
