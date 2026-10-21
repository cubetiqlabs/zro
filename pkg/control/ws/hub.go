// Package ws streams control-plane events to WebSocket clients.
package ws

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cubis/zro/pkg/control/events"
	"golang.org/x/net/websocket"
)

const writeTimeout = 10 * time.Second

// Serve upgrades an already-authenticated request and streams the events
// visible to sub until the client or the subscription goes away. The caller
// owns authentication; the hello frame is only sent after the upgrade.
func Serve(w http.ResponseWriter, r *http.Request, sub *events.Subscription, allowedOrigins []string) {
	defer sub.Close()

	srv := websocket.Server{
		Handshake: func(cfg *websocket.Config, req *http.Request) error {
			if !originAllowed(req, allowedOrigins) {
				return errors.New("origin not allowed")
			}
			return nil
		},
		Handler: func(conn *websocket.Conn) {
			defer conn.Close()

			// Reader goroutine: answers keepalives and detects disconnects.
			done := make(chan struct{})
			go func() {
				defer close(done)
				var msg string
				for websocket.Message.Receive(conn, &msg) == nil {
					if msg == "ping" {
						_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
						_ = websocket.Message.Send(conn, "pong")
					}
				}
			}()

			send := func(v any) error {
				_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
				return websocket.JSON.Send(conn, v)
			}
			if send(events.Message{Event: "connected", Timestamp: time.Now(), Data: []byte(`{"transport":"websocket"}`)}) != nil {
				return
			}
			for {
				select {
				case <-done:
					return
				case msg, ok := <-sub.C:
					if !ok || send(msg) != nil {
						return
					}
				}
			}
		},
	}
	srv.ServeHTTP(w, r)
}

// originAllowed accepts non-browser clients (no Origin), same-origin
// requests, and explicitly allow-listed origins.
func originAllowed(r *http.Request, allowed []string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	for _, a := range allowed {
		if strings.EqualFold(strings.TrimRight(a, "/"), strings.TrimRight(origin, "/")) {
			return true
		}
	}
	return false
}
