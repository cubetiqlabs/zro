package ws

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

// EventMessage represents a real-time event frame broadcast over WebSockets.
type EventMessage struct {
	Event     string    `json:"event"`
	Timestamp time.Time `json:"timestamp"`
	Data      any       `json:"data"`
}

// Hub coordinates active WebSocket client sessions and broadcasts events in real-time.
type Hub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]bool
}

// NewHub creates a new WebSocket connection hub.
func NewHub() *Hub {
	return &Hub{
		clients: make(map[*websocket.Conn]bool),
	}
}

// Handler returns an http.Handler that upgrades incoming HTTP connections to WebSockets.
func (h *Hub) Handler() http.Handler {
	return websocket.Handler(func(ws *websocket.Conn) {
		h.mu.Lock()
		h.clients[ws] = true
		h.mu.Unlock()

		defer func() {
			h.mu.Lock()
			delete(h.clients, ws)
			h.mu.Unlock()
			_ = ws.Close()
		}()

		// Send initial connected handshake
		welcome := EventMessage{
			Event:     "connected",
			Timestamp: time.Now(),
			Data:      map[string]string{"status": "authenticated", "transport": "websocket"},
		}
		_ = websocket.JSON.Send(ws, welcome)

		// Read loop for client keepalive / ping
		var msg string
		for {
			err := websocket.Message.Receive(ws, &msg)
			if err != nil {
				break
			}
			if msg == "ping" {
				_ = websocket.Message.Send(ws, "pong")
			}
		}
	})
}

// Broadcast sends an event payload to all connected WebSocket clients.
func (h *Hub) Broadcast(event string, data any) {
	msg := EventMessage{
		Event:     event,
		Timestamp: time.Now(),
		Data:      data,
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for ws := range h.clients {
		_ = websocket.Message.Send(ws, string(payload))
	}
}

// ClientCount returns the number of active WebSocket connections.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}
