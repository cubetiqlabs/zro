package ws

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

func TestWebSocketHubRealtimeBroadcast(t *testing.T) {
	hub := NewHub()
	server := httptest.NewServer(hub.Handler())
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Connect client 1
	ws1, err := websocket.Dial(wsURL, "", server.URL)
	if err != nil {
		t.Fatalf("failed to connect ws1: %v", err)
	}
	defer ws1.Close()

	// Connect client 2
	ws2, err := websocket.Dial(wsURL, "", server.URL)
	if err != nil {
		t.Fatalf("failed to connect ws2: %v", err)
	}
	defer ws2.Close()

	time.Sleep(50 * time.Millisecond)
	if count := hub.ClientCount(); count != 2 {
		t.Fatalf("expected 2 connected clients, got %d", count)
	}

	// Read initial welcome messages
	var welcome1, welcome2 EventMessage
	_ = websocket.JSON.Receive(ws1, &welcome1)
	_ = websocket.JSON.Receive(ws2, &welcome2)

	if welcome1.Event != "connected" || welcome2.Event != "connected" {
		t.Fatalf("expected welcome 'connected' event, got ws1=%s, ws2=%s", welcome1.Event, welcome2.Event)
	}

	// Broadcast test real-time event (e.g. gateway_routes_updated)
	hub.Broadcast("gateway_routes_updated", map[string]string{
		"hostname": "myapp-api.example.com",
		"backends": "100.64.0.10:3000",
	})

	// Both clients should receive the broadcast event immediately
	var event1, event2 EventMessage
	var rawMsg string
	_ = websocket.Message.Receive(ws1, &rawMsg)
	_ = json.Unmarshal([]byte(rawMsg), &event1)

	_ = websocket.Message.Receive(ws2, &rawMsg)
	_ = json.Unmarshal([]byte(rawMsg), &event2)

	if event1.Event != "gateway_routes_updated" || event2.Event != "gateway_routes_updated" {
		t.Fatalf("expected 'gateway_routes_updated' event, got ws1=%s, ws2=%s", event1.Event, event2.Event)
	}

	// Test ping/pong keepalive
	_ = websocket.Message.Send(ws1, "ping")
	var pongResp string
	_ = websocket.Message.Receive(ws1, &pongResp)
	if pongResp != "pong" {
		t.Fatalf("expected 'pong', got %s", pongResp)
	}
	t.Log("✅ WebSocket Hub verified: real-time streaming broadcast and keepalive working")
}
