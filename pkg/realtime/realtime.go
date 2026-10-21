// Package realtime subscribes an agent to the control plane's event stream and
// turns bursts of events into a single refresh. Edge, gateway and node agents
// share it, so reconnect, backoff and keepalive behave the same everywhere.
package realtime

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/url"
	"time"

	v1 "github.com/cubis/zro/api/proto/v1"
	controlgrpc "github.com/cubis/zro/pkg/control/grpc"
	"golang.org/x/net/websocket"
)

// Config describes one subscription.
type Config struct {
	// Endpoint is the plane's REST base URL; used for the WebSocket transport.
	Endpoint string
	// GRPC selects the gRPC stream instead of WebSocket when non-nil.
	GRPC *controlgrpc.Client
	// Role and ID identify the subscriber in plane logs.
	Role, ID string
	// Credential returns the bearer secret (node token or per-PoP key).
	Credential func() string
	// Events restricts which event names trigger the handler; empty means all.
	Events []string
	// Debounce batches events arriving close together (default 100ms).
	Debounce time.Duration
	// Raw, if set, receives every wanted event with its JSON payload
	// immediately (unbatched), for events whose content matters.
	Raw func(name string, data json.RawMessage)
}

const (
	minBackoff   = time.Second
	maxBackoff   = 30 * time.Second
	pingInterval = 30 * time.Second
	readTimeout  = 3 * pingInterval
)

// Run delivers batches of event names to handle until ctx ends, reconnecting
// with jittered exponential backoff whenever the stream drops. handle is never
// called concurrently with itself, and events that arrive while it runs are
// folded into the next call.
func Run(ctx context.Context, cfg Config, handle func(ctx context.Context, events []string)) {
	if cfg.Debounce == 0 {
		cfg.Debounce = 100 * time.Millisecond
	}
	wanted := make(map[string]bool, len(cfg.Events))
	for _, e := range cfg.Events {
		wanted[e] = true
	}

	b := newBatcher(cfg.Debounce, handle)
	go b.run(ctx)

	onEvent := func(name string, data json.RawMessage) {
		if len(wanted) == 0 || wanted[name] {
			if cfg.Raw != nil {
				cfg.Raw(name, data)
			}
			b.add(name)
		}
	}

	backoff := minBackoff
	for ctx.Err() == nil {
		started := time.Now()
		var err error
		if cfg.GRPC != nil {
			err = cfg.GRPC.StreamEvents(ctx, cfg.Role, cfg.ID, func(e *v1.MeshEvent) {
				if e != nil {
					onEvent(e.EventType, json.RawMessage(e.PayloadJson))
				}
			})
		} else {
			err = streamWebSocket(ctx, cfg, onEvent)
		}
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > 10*time.Second {
			backoff = minBackoff // it was healthy for a while; retry quickly
		}
		slog.Debug("Event stream ended; reconnecting", "role", cfg.Role, "error", err, "in", backoff)
		sleep(ctx, jitter(backoff))
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// wsURL converts the REST base URL to the plane's WebSocket endpoint.
func wsURL(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid plane endpoint %q", endpoint)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("unsupported plane endpoint scheme %q", u.Scheme)
	}
	u.Path = "/api/v1/ws"
	return u.String(), nil
}

func streamWebSocket(ctx context.Context, cfg Config, onEvent func(string, json.RawMessage)) error {
	target, err := wsURL(cfg.Endpoint)
	if err != nil {
		return err
	}
	wsCfg, err := websocket.NewConfig(target, cfg.Endpoint)
	if err != nil {
		return err
	}
	wsCfg.Dialer = &net.Dialer{Timeout: 10 * time.Second}
	if cfg.Credential != nil {
		if cred := cfg.Credential(); cred != "" {
			wsCfg.Header.Set("Authorization", "Bearer "+cred)
		}
	}
	conn, err := websocket.DialConfig(wsCfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Unblock the read loop on shutdown, and detect half-open connections by
	// pinging: the plane answers "pong", which refreshes the read deadline.
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = conn.Close()
				return
			case <-done:
				return
			case <-ticker.C:
				_ = websocket.Message.Send(conn, "ping")
			}
		}
	}()

	for {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		var raw string
		if err := websocket.Message.Receive(conn, &raw); err != nil {
			return err
		}
		var msg struct {
			Event string          `json:"event"`
			Data  json.RawMessage `json:"data"`
		}
		if json.Unmarshal([]byte(raw), &msg) == nil && msg.Event != "" {
			onEvent(msg.Event, msg.Data)
		}
	}
}

func jitter(d time.Duration) time.Duration {
	return d + time.Duration(rand.Int63n(int64(d)/5+1)) // up to +20%
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
