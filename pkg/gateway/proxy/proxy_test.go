package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cubetiqlabs/zro/pkg/gateway/balancer"
)

func TestReverseProxyEngine(t *testing.T) {
	// 1. Create two mock backend servers
	b1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "response-from-backend-1")
	}))
	defer b1.Close()

	b2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "response-from-backend-2")
	}))
	defer b2.Close()

	// Strip "http://" for balancer address
	b1Addr := b1.Listener.Addr().String()
	b2Addr := b2.Listener.Addr().String()

	backends := []*balancer.Backend{
		{Address: b1Addr, Healthy: true, Weight: 10, Latency: 5 * time.Millisecond},
		{Address: b2Addr, Healthy: true, Weight: 10, Latency: 10 * time.Millisecond},
	}

	bal := balancer.NewBalancer(balancer.StrategyRoundRobin, backends)
	engine := NewEngine()
	engine.RegisterRoute("app.cubis.tech", bal)

	// 2. Perform proxy requests
	req1 := httptest.NewRequest("GET", "http://app.cubis.tech/api", nil)
	rec1 := httptest.NewRecorder()
	engine.ServeHTTP(rec1, req1)

	resp1, _ := io.ReadAll(rec1.Body)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec1.Code)
	}

	req2 := httptest.NewRequest("GET", "http://app.cubis.tech/api", nil)
	rec2 := httptest.NewRecorder()
	engine.ServeHTTP(rec2, req2)

	resp2, _ := io.ReadAll(rec2.Body)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec2.Code)
	}

	// Because of RoundRobin, one should be b1 and one should be b2
	if string(resp1) == string(resp2) {
		t.Fatalf("expected round robin distribution across different backends, got %s and %s", resp1, resp2)
	}
}
