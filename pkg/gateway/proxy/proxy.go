package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cubetiqlabs/zro/pkg/gateway/balancer"
)

// Engine serves as the core reverse proxy gateway.
type Engine struct {
	mu        sync.RWMutex
	routes    map[string]*balancer.Balancer // hostname -> balancer
	Transport *http.Transport
}

// NewEngine creates a new reverse proxy gateway engine.
func NewEngine() *Engine {
	return &Engine{
		routes: make(map[string]*balancer.Balancer),
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// RegisterRoute maps a hostname to a load balancer.
func (e *Engine) RegisterRoute(hostname string, bal *balancer.Balancer) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.routes[hostname] = bal
}

// GetRoute retrieves a balancer for a given hostname.
func (e *Engine) GetRoute(hostname string) (*balancer.Balancer, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	b, ok := e.routes[hostname]
	return b, ok
}

// ListRoutes returns a snapshot of all registered routes.
func (e *Engine) ListRoutes() map[string]*balancer.Balancer {
	e.mu.RLock()
	defer e.mu.RUnlock()
	res := make(map[string]*balancer.Balancer, len(e.routes))
	for k, v := range e.routes {
		res[k] = v
	}
	return res
}

// UnregisterRoute removes a hostname mapping.
func (e *Engine) UnregisterRoute(hostname string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.routes, hostname)
}

// ServeHTTP satisfies http.Handler and proxies traffic to the target mesh backend.
func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	// Strip port from host if present
	if h, _, err := netSplitHost(host); err == nil {
		host = h
	}

	e.mu.RLock()
	bal, exists := e.routes[host]
	e.mu.RUnlock()

	if !exists {
		http.Error(w, fmt.Sprintf("no route configured for host %q", host), http.StatusBadGateway)
		return
	}

	backend, err := bal.Pick(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("no healthy backends available: %v", err), http.StatusServiceUnavailable)
		return
	}

	// Track connection count & latency
	atomic.AddInt64(&backend.ActiveConns, 1)
	defer atomic.AddInt64(&backend.ActiveConns, -1)

	targetURL, err := url.Parse("http://" + backend.Address)
	if err != nil {
		http.Error(w, "invalid backend address", http.StatusInternalServerError)
		return
	}

	start := time.Now()
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	if e.Transport != nil {
		proxy.Transport = e.Transport
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
		slog.Error("Proxy error forwarding to mesh backend", "backend", backend.Address, "error", proxyErr)
		backend.Healthy = false // Instant failover mark
		rw.WriteHeader(http.StatusBadGateway)
		_, _ = rw.Write([]byte("502 Bad Gateway - Target mesh node unreachable\n"))
	}

	proxy.ServeHTTP(w, r)
	backend.Latency = time.Since(start)
}

func netSplitHost(hostport string) (string, string, error) {
	for i := len(hostport) - 1; i >= 0; i-- {
		if hostport[i] == ':' {
			return hostport[:i], hostport[i+1:], nil
		}
	}
	return hostport, "", nil
}

// HealthChecker periodically probes backends and marks their health.
type HealthChecker struct {
	client *http.Client
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
}

// SetDialer routes health probes through dial (for example the overlay stack
// of a userspace gateway) instead of the host network.
func (h *HealthChecker) SetDialer(dial func(ctx context.Context, network, addr string) (net.Conn, error)) {
	h.dial = dial
	h.client.Transport = &http.Transport{DialContext: dial}
}

// NewHealthChecker creates a health check worker.
func NewHealthChecker(timeout time.Duration) *HealthChecker {
	return &HealthChecker{
		client: &http.Client{Timeout: timeout},
	}
}

// Check probes a backend address and updates its status.
func (h *HealthChecker) Check(ctx context.Context, b *balancer.Backend, healthPath string) bool {
	if healthPath == "" {
		healthPath = "/health"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+b.Address+healthPath, nil)
	if err != nil {
		b.Healthy = false
		return false
	}

	start := time.Now()
	resp, err := h.client.Do(req)
	if err != nil {
		// Fallback to TCP dial probe
		dial := h.dial
		if dial == nil {
			dial = (&net.Dialer{}).DialContext
		}
		conn, dialErr := dial(ctx, "tcp", b.Address)
		if dialErr != nil {
			b.Healthy = false
			return false
		}
		_ = conn.Close()
		b.Healthy = true
		b.Latency = time.Since(start)
		return true
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		b.Healthy = false
		return false
	}

	b.Healthy = true
	b.Latency = time.Since(start)
	return true
}
