package edge

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/cubetiqlabs/zro/pkg/config"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/cubetiqlabs/zro/pkg/crypto"
	"github.com/cubetiqlabs/zro/pkg/p2p/stun"
)

func TestEdgePoPDaemonLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var registeredPoP, heartbeatPoP string

	mockPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/edge/register":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			registeredPoP, _ = req["pop_code"].(string)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case "/api/v1/edge/heartbeat":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			heartbeatPoP, _ = req["pop_code"].(string)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case "/api/v1/edge/sync":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"pops": []core.EdgePoP{
					{PoPCode: "SG", PublicKey: "sg-pubkey", PublicEndpoint: "123.1.1.1:51820"},
				},
				"nodes": []core.Node{
					{Hostname: "node-01", PublicKey: "node-pubkey", OverlayIPv4: "100.64.0.5", Endpoints: core.StringList{"192.168.1.10:51820"}},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockPlane.Close()

	kp, _ := crypto.GenerateKeyPair()

	// Find an available local UDP/TCP port
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	cfg := &config.EdgeConfig{
		PoPCode:             "KH",
		Region:              "Cambodia",
		PublicEndpoint:      "127.0.0.1:51820",
		ListenPort:          port,
		WireGuardPrivateKey: kp.PrivateKey,
		PlaneEndpoint:       mockPlane.URL,
		UsePrivateIP:        true,
	}

	daemon, err := NewPoPDaemon(cfg)
	if err != nil {
		t.Fatalf("NewPoPDaemon failed: %v", err)
	}

	if daemon.PublicKey() != kp.PublicKey {
		t.Fatalf("expected pubkey %s, got %s", kp.PublicKey, daemon.PublicKey())
	}

	if err := daemon.Start(ctx); err != nil {
		t.Fatalf("daemon.Start failed: %v", err)
	}
	defer daemon.Stop()

	// Give background worker time to register and sync
	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	reg := registeredPoP
	hb := heartbeatPoP
	mu.Unlock()

	if reg != "KH" {
		t.Fatalf("expected Edge PoP KH to register, got %s", reg)
	}
	if hb != "KH" && hb != "" {
		t.Fatalf("unexpected heartbeat PoP %s", hb)
	}

	// Test STUN resolution against the Edge PoP UDP listener using IPv4 loopback
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to bind STUN client UDP socket: %v", err)
	}
	defer clientConn.Close()

	edgePort := daemon.udpListener.LocalAddr().(*net.UDPAddr).Port
	edgeUDPAddr := fmt.Sprintf("127.0.0.1:%d", edgePort)
	discovered, err := stun.DiscoverPublicEndpoint(clientConn, edgeUDPAddr, 1*time.Second)
	if err != nil || discovered == nil {
		t.Fatalf("STUN discovery against Edge PoP failed: %v", err)
	}

	// Verify Stop cleans up without panic or hang
	if err := daemon.Stop(); err != nil {
		t.Fatalf("daemon.Stop failed: %v", err)
	}
}
