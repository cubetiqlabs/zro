package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"

	"github.com/google/uuid"
)

// IngressDefinition describes an exposed service.
type IngressDefinition struct {
	ID             uuid.UUID `json:"id"`
	NodeID         uuid.UUID `json:"node_id"`
	Name           string    `json:"name"`
	LocalAddress   string    `json:"local_address"`   // e.g. "127.0.0.1:8080"
	PublicHostname string    `json:"public_hostname"` // e.g. "api.cubis.tech"
	Protocol       string    `json:"protocol"`        // only "http"
}

// Client manages local service forwarding on a node.
type Client struct {
	mu      sync.RWMutex
	tunnels map[string]IngressDefinition // hostname -> tunnel
	proxies map[string]*httputil.ReverseProxy
}

// NewClient creates a new tunnel forwarding client.
func NewClient() *Client {
	return &Client{
		tunnels: make(map[string]IngressDefinition),
		proxies: make(map[string]*httputil.ReverseProxy),
	}
}

// ExposeService registers a local service for tunnel forwarding.
func (c *Client) ExposeService(t IngressDefinition) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	targetURL, err := url.Parse("http://" + t.LocalAddress)
	if err != nil {
		return fmt.Errorf("invalid local address: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		slog.Error("Tunnel proxy failed to reach local backend", "backend", t.LocalAddress, "error", err)
		http.Error(w, "502 Bad Gateway - Local service unreachable", http.StatusBadGateway)
	}

	c.tunnels[t.PublicHostname] = t
	c.proxies[t.PublicHostname] = proxy
	slog.Info("Tunnel service exposed", "name", t.Name, "hostname", t.PublicHostname, "local", t.LocalAddress)
	return nil
}

// ServeHTTP proxies incoming requests to the local backend based on hostname.
func (c *Client) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.RLock()
	proxy, exists := c.proxies[r.Host]
	c.mu.RUnlock()

	if !exists {
		// Strip port if present
		h, _, err := net.SplitHostPort(r.Host)
		if err == nil {
			c.mu.RLock()
			proxy = c.proxies[h]
			c.mu.RUnlock()
		}
	}

	if proxy == nil {
		http.Error(w, fmt.Sprintf("no tunnel registered for hostname %q", r.Host), http.StatusNotFound)
		return
	}

	proxy.ServeHTTP(w, r)
}

// PipeTCP bridges a raw TCP connection to a local service address and closes
// both ends when it returns. Each direction is copied until EOF and then
// half-closed, so a client that finishes sending can still receive the reply.
func (c *Client) PipeTCP(ctx context.Context, incoming net.Conn, localAddress string) error {
	defer incoming.Close()
	var d net.Dialer
	upstream, err := d.DialContext(ctx, "tcp", localAddress)
	if err != nil {
		return fmt.Errorf("failed to dial local service %s: %w", localAddress, err)
	}
	defer upstream.Close()

	return bridge(incoming, upstream, ctx)
}

// bridge copies a<->b until both directions finish. Each direction half-closes
// its destination at EOF, so a peer that finished sending can still receive the
// reply; a real error (or ctx ending) tears both connections down. It returns
// the first real error.
func bridge(a, b net.Conn, ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() {
		_ = a.Close()
		_ = b.Close()
	})
	defer stop()

	errCh := make(chan error, 2)
	pipe := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite() // propagate EOF without cutting the other direction
		}
		errCh <- err
	}
	go pipe(a, b)
	go pipe(b, a)

	var first error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && first == nil && ctx.Err() == nil {
			first = err
			_ = a.Close()
			_ = b.Close()
		}
	}
	return first
}
