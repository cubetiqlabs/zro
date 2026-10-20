package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/cubis/zro/pkg/config"
	"github.com/cubis/zro/pkg/control/server"
	"github.com/google/uuid"
)

func TestGatewayStaticAndDynamicRoutes(t *testing.T) {
	ctx := context.Background()

	// 1. Setup Mock Backends: node1 and node2 running myapp-api
	var node1Hits, node2Hits int64
	node1Active := int32(1)

	node1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&node1Active) == 0 {
			http.Error(w, "node1 down", http.StatusServiceUnavailable)
			return
		}
		atomic.AddInt64(&node1Hits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "node1 response")
	}))
	defer node1.Close()

	node2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&node2Hits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "node2 response")
	}))
	defer node2.Close()

	// 2. Mock Control Plane serving dynamic routes
	mockPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/gateway/routes" {
			resp := server.GatewayRoutesResponse{
				Routes: []server.GatewayRouteItem{
					{
						Hostname: "myapp-api.example.com",
						Protocol: "http",
						Backends: []server.GatewayBackendItem{
							{
								Address:      node1.Listener.Addr().String(),
								NodeID:       uuid.New(),
								NodeHostname: "node1",
								Weight:       100,
								Healthy:      true,
							},
							{
								Address:      node2.Listener.Addr().String(),
								NodeID:       uuid.New(),
								NodeHostname: "node2",
								Weight:       100,
								Healthy:      true,
							},
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer mockPlane.Close()

	// 3. Initialize Gateway 1 (gw1)
	cfg1 := &config.GatewayConfig{
		Hostname:              "gw1",
		PlaneEndpoint:         mockPlane.URL,
		Strategy:              "round_robin",
		HealthCheckPath:       "/",
		HealthCheckIntervalMs: 100,
		StaticRoutes: []config.StaticRouteConfig{
			{
				Hostname: "static.example.com",
				Strategy: "round_robin",
				Backends: []string{node1.Listener.Addr().String()},
			},
		},
	}

	gw1, err := NewDaemon(cfg1)
	if err != nil {
		t.Fatalf("failed to create gw1: %v", err)
	}

	// Verify static route loaded
	balStatic, exists := gw1.ProxyEngine().GetRoute("static.example.com")
	if !exists || len(balStatic.GetBackends()) != 1 {
		t.Fatalf("expected static route loaded with 1 backend")
	}

	// 4. Test Dynamic Route Sync
	if err := gw1.SyncRoutesOnce(ctx); err != nil {
		t.Fatalf("SyncRoutesOnce failed: %v", err)
	}

	balDynamic, exists := gw1.ProxyEngine().GetRoute("myapp-api.example.com")
	if !exists {
		t.Fatalf("expected dynamic route myapp-api.example.com to be registered")
	}
	if len(balDynamic.GetBackends()) != 2 {
		t.Fatalf("expected 2 backends for clustered myapp-api, got %d", len(balDynamic.GetBackends()))
	}

	// 5. Proxy traffic across the cluster (load balanced)
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest("GET", "http://myapp-api.example.com/test", nil)
		rec := httptest.NewRecorder()
		gw1.ProxyEngine().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d failed: status %d", i, rec.Code)
		}
	}

	if atomic.LoadInt64(&node1Hits) == 0 || atomic.LoadInt64(&node2Hits) == 0 {
		t.Fatalf("expected both node1 and node2 to receive traffic in cluster, got node1=%d, node2=%d",
			atomic.LoadInt64(&node1Hits), atomic.LoadInt64(&node2Hits))
	}
	t.Logf("✅ Clustered multi-node traffic distributed: node1=%d, node2=%d",
		atomic.LoadInt64(&node1Hits), atomic.LoadInt64(&node2Hits))

	// 6. Active Failover Test: Simulate node1 crash
	atomic.StoreInt32(&node1Active, 0)

	// Health check probes all backends
	for _, b := range balDynamic.GetBackends() {
		gw1.healthChecker.Check(ctx, b, "/")
	}

	// Node 1 should be marked unhealthy, node 2 healthy
	backends := balDynamic.GetBackends()
	var n1Healthy, n2Healthy bool
	for _, b := range backends {
		if b.Address == node1.Listener.Addr().String() {
			n1Healthy = b.Healthy
		}
		if b.Address == node2.Listener.Addr().String() {
			n2Healthy = b.Healthy
		}
	}

	if n1Healthy {
		t.Fatalf("expected node1 to be marked unhealthy after crash")
	}
	if !n2Healthy {
		t.Fatalf("expected node2 to remain healthy")
	}

	// Request should immediately succeed via node2 without downtime!
	prevNode2Hits := atomic.LoadInt64(&node2Hits)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "http://myapp-api.example.com/test", nil)
		rec := httptest.NewRecorder()
		gw1.ProxyEngine().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("failover request %d failed: status %d", i, rec.Code)
		}
		body, _ := io.ReadAll(rec.Body)
		if string(body) != "node2 response" {
			t.Fatalf("expected failover to node2 response, got %s", string(body))
		}
	}

	if atomic.LoadInt64(&node2Hits) != prevNode2Hits+5 {
		t.Fatalf("expected node2 to absorb all traffic during node1 failure")
	}
	t.Log("✅ Zero-downtime failover verified: Traffic shifted 100% to node2")

	// 7. Multi-Gateway High Availability: Start Gateway 2 (gw2)
	cfg2 := &config.GatewayConfig{
		Hostname:      "gw2",
		PlaneEndpoint: mockPlane.URL,
		Strategy:      "round_robin",
	}
	gw2, err := NewDaemon(cfg2)
	if err != nil {
		t.Fatalf("failed to create gw2: %v", err)
	}

	if err := gw2.SyncRoutesOnce(ctx); err != nil {
		t.Fatalf("gw2 SyncRoutesOnce failed: %v", err)
	}

	// gw2 also serves the exact same domain
	gw2Bal, exists := gw2.ProxyEngine().GetRoute("myapp-api.example.com")
	if !exists || len(gw2Bal.GetBackends()) != 2 {
		t.Fatalf("gw2 expected to have identical clustered routes for myapp-api.example.com")
	}

	reqGW2 := httptest.NewRequest("GET", "http://myapp-api.example.com/api", nil)
	recGW2 := httptest.NewRecorder()
	gw2.ProxyEngine().ServeHTTP(recGW2, reqGW2)
	if recGW2.Code != http.StatusOK {
		t.Fatalf("gw2 request failed: %d", recGW2.Code)
	}
	t.Log("✅ Multi-gateway HA verified: gw2 serving identical dynamic cluster routes")

	_ = gw1.Stop()
	_ = gw2.Stop()
}
