package balancer

import (
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrNoHealthyBackends = errors.New("no healthy backends available")
)

// Strategy defines load balancing strategy.
type Strategy string

const (
	StrategyRoundRobin Strategy = "round_robin"
	StrategyLeastConn  Strategy = "least_conn"
	StrategyLatency    Strategy = "latency"
)

// Backend represents a target upstream service in the mesh.
type Backend struct {
	Address     string        `json:"address"` // e.g. "100.64.0.10:8080"
	Weight      int           `json:"weight"`
	ActiveConns int64         `json:"active_conns"`
	Latency     time.Duration `json:"latency"`
	Healthy     bool          `json:"healthy"`
}

// Balancer distributes requests across healthy backends.
type Balancer struct {
	mu        sync.RWMutex
	strategy  Strategy
	backends  []*Backend
	rrCounter uint64
}

// NewBalancer creates a new load balancer.
func NewBalancer(strategy Strategy, backends []*Backend) *Balancer {
	if strategy == "" {
		strategy = StrategyRoundRobin
	}
	return &Balancer{
		strategy: strategy,
		backends: backends,
	}
}

// UpdateBackends updates the backend pool while preserving state of existing backends.
func (b *Balancer) UpdateBackends(backends []*Backend) {
	b.mu.Lock()
	defer b.mu.Unlock()

	existing := make(map[string]*Backend)
	for _, old := range b.backends {
		existing[old.Address] = old
	}

	for _, nb := range backends {
		if old, ok := existing[nb.Address]; ok {
			nb.Healthy = old.Healthy
			nb.Latency = old.Latency
			atomic.StoreInt64(&nb.ActiveConns, atomic.LoadInt64(&old.ActiveConns))
		}
	}

	b.backends = backends
}

// GetBackends returns a snapshot of all backends.
func (b *Balancer) GetBackends() []*Backend {
	b.mu.RLock()
	defer b.mu.RUnlock()
	res := make([]*Backend, len(b.backends))
	copy(res, b.backends)
	return res
}

// Strategy returns the configured balancing strategy.
func (b *Balancer) Strategy() Strategy {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.strategy
}

// Pick selects a backend according to the chosen strategy.
func (b *Balancer) Pick(r *http.Request) (*Backend, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var healthy []*Backend
	for _, backend := range b.backends {
		if backend.Healthy {
			healthy = append(healthy, backend)
		}
	}

	if len(healthy) == 0 {
		return nil, ErrNoHealthyBackends
	}

	switch b.strategy {
	case StrategyLeastConn:
		best := healthy[0]
		minConns := atomic.LoadInt64(&best.ActiveConns)
		for _, candidate := range healthy[1:] {
			c := atomic.LoadInt64(&candidate.ActiveConns)
			if c < minConns {
				best = candidate
				minConns = c
			}
		}
		return best, nil

	case StrategyLatency:
		best := healthy[0]
		for _, candidate := range healthy[1:] {
			if candidate.Latency < best.Latency {
				best = candidate
			}
		}
		return best, nil

	case StrategyRoundRobin:
		fallthrough
	default:
		idx := atomic.AddUint64(&b.rrCounter, 1) % uint64(len(healthy))
		return healthy[idx], nil
	}
}
