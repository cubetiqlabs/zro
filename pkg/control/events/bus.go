package events

import (
	"encoding/json"
	"sync"
	"time"
)

// subscriberBuffer bounds how far a consumer may lag before it is dropped.
const subscriberBuffer = 64

// Message is the wire frame shared by every event transport.
type Message struct {
	Event     string          `json:"event"`
	Timestamp time.Time       `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

// Bus fans events out to scoped subscribers. SSE, WebSocket and gRPC streams
// all subscribe here so tenant filtering lives in exactly one place.
type Bus struct {
	mu   sync.RWMutex
	subs map[*Subscription]struct{}
}

// NewBus creates an empty event bus.
func NewBus() *Bus {
	return &Bus{subs: make(map[*Subscription]struct{})}
}

// Subscription receives the events visible to its scope. C is closed when the
// subscription is closed or when the consumer fell too far behind.
type Subscription struct {
	C     <-chan Message
	ch    chan Message
	scope Scope
	bus   *Bus
}

// Subscribe registers a subscriber limited to scope.
func (b *Bus) Subscribe(scope Scope) *Subscription {
	ch := make(chan Message, subscriberBuffer)
	sub := &Subscription{C: ch, ch: ch, scope: scope, bus: b}
	b.mu.Lock()
	b.subs[sub] = struct{}{}
	b.mu.Unlock()
	return sub
}

// Close unregisters the subscription. It is safe to call more than once.
func (s *Subscription) Close() {
	s.bus.mu.Lock()
	defer s.bus.mu.Unlock()
	if _, ok := s.bus.subs[s]; ok {
		delete(s.bus.subs, s)
		close(s.ch)
	}
}

// Len returns the number of active subscriptions.
func (b *Bus) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}

// Publish delivers an event to every subscriber whose scope matches. A
// subscriber with a full buffer is disconnected instead of silently losing
// events; it must reconnect and resync.
func (b *Bus) Publish(scope Scope, event string, data any) {
	payload, err := json.Marshal(data)
	if err != nil {
		return
	}
	msg := Message{Event: event, Timestamp: time.Now(), Data: payload}

	var slow []*Subscription
	b.mu.RLock()
	for sub := range b.subs {
		if !sub.scope.Matches(scope) {
			continue
		}
		select {
		case sub.ch <- msg:
		default:
			slow = append(slow, sub)
		}
	}
	b.mu.RUnlock()

	for _, sub := range slow {
		sub.Close()
	}
}
