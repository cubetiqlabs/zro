package ws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cubetiqlabs/zro/pkg/control/events"
	"github.com/google/uuid"
	"golang.org/x/net/websocket"
)

func TestServeScopedBroadcastAndOrigin(t *testing.T) {
	bus := events.NewBus()
	tenant := uuid.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Serve(w, r, bus.Subscribe(events.ForTenant(tenant)), nil)
	}))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	// Cross-origin browser request is rejected.
	if _, err := websocket.Dial(wsURL, "", "http://evil.example"); err == nil {
		t.Fatal("cross-origin handshake must be rejected")
	}

	conn, err := websocket.Dial(wsURL, "", srv.URL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	var hello events.Message
	if err := websocket.JSON.Receive(conn, &hello); err != nil || hello.Event != "connected" {
		t.Fatalf("expected connected hello, got %+v err=%v", hello, err)
	}

	bus.Publish(events.Scope{TenantID: uuid.New()}, "other_tenant", nil) // must not arrive
	bus.Publish(events.Scope{TenantID: tenant}, "mine", map[string]string{"a": "b"})

	var got events.Message
	if err := websocket.JSON.Receive(conn, &got); err != nil || got.Event != "mine" {
		t.Fatalf("expected own-tenant event first, got %+v err=%v", got, err)
	}
}
