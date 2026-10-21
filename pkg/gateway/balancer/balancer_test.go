package balancer

import (
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestBalancerRoundRobin(t *testing.T) {
	b1 := &Backend{Address: "100.64.0.1:8080", Healthy: true, Weight: 100}
	b2 := &Backend{Address: "100.64.0.2:8080", Healthy: true, Weight: 100}
	b3 := &Backend{Address: "100.64.0.3:8080", Healthy: true, Weight: 100}

	bal := NewBalancer(StrategyRoundRobin, []*Backend{b1, b2, b3})

	req := httptest.NewRequest("GET", "http://example.com", nil)

	// Round-robin cycle
	picked1, err := bal.Pick(req)
	if err != nil || picked1.Address != "100.64.0.1:8080" {
		t.Fatalf("expected b1, got %v (err: %v)", picked1, err)
	}

	picked2, err := bal.Pick(req)
	if err != nil || picked2.Address != "100.64.0.2:8080" {
		t.Fatalf("expected b2, got %v", picked2)
	}

	picked3, err := bal.Pick(req)
	if err != nil || picked3.Address != "100.64.0.3:8080" {
		t.Fatalf("expected b3, got %v", picked3)
	}

	// Wraps around to b1
	picked4, _ := bal.Pick(req)
	if picked4.Address != "100.64.0.1:8080" {
		t.Fatalf("expected wrap-around to b1, got %v", picked4)
	}

	// Mark b2 as unhealthy -> should cycle b1, b3, b1, b3
	b2.Healthy = false
	picked5, _ := bal.Pick(req)
	picked6, _ := bal.Pick(req)
	if picked5.Address == "100.64.0.2:8080" || picked6.Address == "100.64.0.2:8080" {
		t.Fatalf("unhealthy backend b2 should not be picked")
	}
}

func TestBalancerLeastConn(t *testing.T) {
	b1 := &Backend{Address: "100.64.0.1:8080", Healthy: true, ActiveConns: 10}
	b2 := &Backend{Address: "100.64.0.2:8080", Healthy: true, ActiveConns: 2} // least
	b3 := &Backend{Address: "100.64.0.3:8080", Healthy: true, ActiveConns: 5}

	bal := NewBalancer(StrategyLeastConn, []*Backend{b1, b2, b3})
	req := httptest.NewRequest("GET", "http://example.com", nil)

	picked, err := bal.Pick(req)
	if err != nil || picked.Address != "100.64.0.2:8080" {
		t.Fatalf("expected b2 with least connections (2), got %v (err: %v)", picked, err)
	}

	// Now b2 gets busy (20 conns)
	atomic.StoreInt64(&b2.ActiveConns, 20)
	pickedAfter, _ := bal.Pick(req)
	if pickedAfter.Address != "100.64.0.3:8080" { // b3 has 5 conns
		t.Fatalf("expected b3 with least connections (5), got %v", pickedAfter)
	}
}

func TestBalancerLatency(t *testing.T) {
	b1 := &Backend{Address: "100.64.0.1:8080", Healthy: true, Latency: 45 * time.Millisecond}
	b2 := &Backend{Address: "100.64.0.2:8080", Healthy: true, Latency: 120 * time.Millisecond}
	b3 := &Backend{Address: "100.64.0.3:8080", Healthy: true, Latency: 5 * time.Millisecond} // lowest

	bal := NewBalancer(StrategyLatency, []*Backend{b1, b2, b3})
	req := httptest.NewRequest("GET", "http://example.com", nil)

	picked, err := bal.Pick(req)
	if err != nil || picked.Address != "100.64.0.3:8080" {
		t.Fatalf("expected b3 with lowest latency (5ms), got %v (err: %v)", picked, err)
	}
}

func TestBalancerNoHealthyBackends(t *testing.T) {
	b1 := &Backend{Address: "100.64.0.1:8080", Healthy: false}
	bal := NewBalancer(StrategyRoundRobin, []*Backend{b1})
	req := httptest.NewRequest("GET", "http://example.com", nil)

	_, err := bal.Pick(req)
	if err != ErrNoHealthyBackends {
		t.Fatalf("expected ErrNoHealthyBackends, got %v", err)
	}
}

func TestBalancerUpdateBackends(t *testing.T) {
	b1 := &Backend{Address: "100.64.0.1:8080", Healthy: true, ActiveConns: 5, Latency: 10 * time.Millisecond}
	bal := NewBalancer(StrategyRoundRobin, []*Backend{b1})

	// Update with new list that contains updated b1 and a new b2
	newB1 := &Backend{Address: "100.64.0.1:8080", Healthy: false} // should preserve previous state
	newB2 := &Backend{Address: "100.64.0.2:8080", Healthy: true}
	bal.UpdateBackends([]*Backend{newB1, newB2})

	backends := bal.GetBackends()
	if len(backends) != 2 {
		t.Fatalf("expected 2 backends, got %d", len(backends))
	}
	// Verify b1 state was preserved
	for _, b := range backends {
		if b.Address == "100.64.0.1:8080" {
			if !b.Healthy || b.ActiveConns != 5 || b.Latency != 10*time.Millisecond {
				t.Fatalf("expected preserved state for b1, got %+v", b)
			}
		}
	}
}
