package smoke

import (
	"bytes"
	"context"
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
)

func TestFullMeshSmoke(t *testing.T) {
	ctx := context.Background()

	// 1. Initialize Control Plane with in-memory DB and auto-seed
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
	if err := srv.SeedDefaultData(ctx); err != nil {
		t.Fatalf("smoke: default seed failed: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 2. Smoke Step: Verify Control Plane Health Endpoint
	resp, err := http.Get(ts.URL + "/health")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("smoke: health check failed, status: %v", resp.StatusCode)
	}
	_ = resp.Body.Close()
	t.Log("✅ Smoke Step 1 Passed: Control Plane /health is healthy")

	// 3. Smoke Step: Verify Auto-Seeded Edge PoPs
	resp, err = http.Get(ts.URL + "/api/v1/pops")
	if err != nil {
		t.Fatalf("smoke: failed to fetch PoPs: %v", err)
	}
	var pops []core.EdgePoP
	if err := json.NewDecoder(resp.Body).Decode(&pops); err != nil {
		t.Fatalf("smoke: failed to parse PoPs: %v", err)
	}
	_ = resp.Body.Close()

	if len(pops) < 5 {
		t.Fatalf("smoke: expected 5 global Edge PoPs (KH, SG, US, HK, DE), got %d", len(pops))
	}
	t.Logf("✅ Smoke Step 2 Passed: 5 Global Edge PoPs active (%s, %s, %s, %s, %s)",
		pops[0].PoPCode, pops[1].PoPCode, pops[2].PoPCode, pops[3].PoPCode, pops[4].PoPCode)

	// 4. Smoke Step: Generate Enrollment Token & Enroll Node 1 (Cambodia)
	networkID := "00000000-0000-0000-0000-000000000002"
	token1 := crypto.GenerateEnrollmentToken(secretKey, networkID, "app-node-kh", 1*time.Hour)
	kp1, _ := crypto.GenerateKeyPair()

	enroll1Req := server.EnrollRequest{
		Token:     token1,
		PublicKey: kp1.PublicKey,
		Hostname:  "app-node-kh",
		NodeType:  core.NodeTypePeer,
		Tags:      core.StringList{"tag:web", "env:prod"},
		Endpoints: core.StringList{"192.168.1.100:51820"},
	}

	body1, _ := json.Marshal(enroll1Req)
	resp, err = http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(body1))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("smoke: node 1 enrollment failed, status: %d", resp.StatusCode)
	}

	var enroll1Resp server.EnrollResponse
	_ = json.NewDecoder(resp.Body).Decode(&enroll1Resp)
	_ = resp.Body.Close()

	if enroll1Resp.OverlayIPv4 != "100.64.0.2" {
		t.Fatalf("smoke: expected node 1 IP 100.64.0.2, got %s", enroll1Resp.OverlayIPv4)
	}
	t.Logf("✅ Smoke Step 3 Passed: Node 1 successfully enrolled with IPless static overlay %s", enroll1Resp.OverlayIPv4)

	// 5. Smoke Step: Enroll Node 2 (Singapore)
	token2 := crypto.GenerateEnrollmentToken(secretKey, networkID, "db-node-sg", 1*time.Hour)
	kp2, _ := crypto.GenerateKeyPair()

	enroll2Req := server.EnrollRequest{
		Token:     token2,
		PublicKey: kp2.PublicKey,
		Hostname:  "db-node-sg",
		NodeType:  core.NodeTypePeer,
		Tags:      core.StringList{"tag:db", "env:prod"},
		Endpoints: core.StringList{"10.0.0.50:51820"},
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
	t.Logf("✅ Smoke Step 4 Passed: Node 2 successfully enrolled with IPless static overlay %s", enroll2Resp.OverlayIPv4)

	// 6. Smoke Step: Smart Routing Delegation (Probe Reporting)
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
	t.Log("✅ Smoke Step 5 Passed: Smart routing telemetry accepted and evaluated")

	// 7. Smoke Step: STUN Reflexive Address Discovery
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
	t.Logf("✅ Smoke Step 6 Passed: STUN NAT reflexive discovery verified (%s)", discovered.String())

	// 8. Smoke Step: P2P Hole Punching Simulation
	p2pConn1, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer p2pConn1.Close()
	p2pConn2, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer p2pConn2.Close()

	// Peer 2 responds to Ping
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
	t.Logf("✅ Smoke Step 7 Passed: Direct P2P Hole Punch established (RTT: %v)", p2pResult.RTT)

	// 9. Smoke Step: Ingress Gateway Reverse Proxy & Load Balancer
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
	t.Log("✅ Smoke Step 8 Passed: Cloud-Native Gateway Reverse Proxy & Load Balancer verified")
}
