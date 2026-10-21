package realtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/cubis/zro/pkg/control/events"
	"github.com/cubis/zro/pkg/control/ws"
)

type collector struct {
	mu      sync.Mutex
	batches [][]string
}

func (c *collector) handle(_ context.Context, names []string) {
	c.mu.Lock()
	c.batches = append(c.batches, names)
	c.mu.Unlock()
}

func (c *collector) wait(t *testing.T, n int) [][]string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		if len(c.batches) >= n {
			out := append([][]string(nil), c.batches...)
			c.mu.Unlock()
			return out
		}
		c.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d batches, got %v", n, c.batches)
	return nil
}

func TestBatchesFiltersAndReconnects(t *testing.T) {
	bus := events.NewBus()
	connected := make(chan struct{}, 4)
	dropFirst := make(chan *events.Subscription, 1) // the first connection's subscription, closed by the test
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sub := bus.Subscribe(events.Global())
		select {
		case dropFirst <- sub:
		default:
		}
		connected <- struct{}{}
		ws.Serve(w, r, sub, nil)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &collector{}
	go Run(ctx, Config{Endpoint: srv.URL, Role: "test", ID: "t", Events: []string{"a", "b"}, Debounce: 50 * time.Millisecond}, c.handle)

	<-connected
	time.Sleep(100 * time.Millisecond) // let the handshake finish

	// A burst becomes one call; unwanted events are dropped.
	bus.Publish(events.Scope{}, "a", nil)
	bus.Publish(events.Scope{}, "ignored", nil)
	bus.Publish(events.Scope{}, "b", nil)
	bus.Publish(events.Scope{}, "a", nil)
	if got := c.wait(t, 1)[0]; !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("expected one coalesced batch [a b], got %v", got)
	}

	// Dropping the connection must not end the subscription.
	(<-dropFirst).Close() // the server ends the first stream
	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		t.Fatal("client did not reconnect")
	}
	time.Sleep(100 * time.Millisecond)
	bus.Publish(events.Scope{}, "b", nil)
	if got := c.wait(t, 2)[1]; !reflect.DeepEqual(got, []string{"b"}) {
		t.Fatalf("expected [b] after reconnect, got %v", got)
	}
}

func TestWSURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://plane.example.com":      "wss://plane.example.com/api/v1/ws",
		"http://127.0.0.1:8443":          "ws://127.0.0.1:8443/api/v1/ws",
		"https://plane.example.com/base": "wss://plane.example.com/api/v1/ws",
	} {
		if got, err := wsURL(in); err != nil || got != want {
			t.Errorf("wsURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := wsURL("ftp://x"); err == nil {
		t.Error("unsupported schemes must be rejected")
	}
}
