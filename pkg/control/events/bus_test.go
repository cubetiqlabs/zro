package events

import (
	"testing"

	"github.com/google/uuid"
)

func recv(t *testing.T, sub *Subscription) (Message, bool) {
	t.Helper()
	select {
	case m, ok := <-sub.C:
		return m, ok
	default:
		return Message{}, false
	}
}

func TestBusTenantIsolation(t *testing.T) {
	bus := NewBus()
	tenantA, tenantB := uuid.New(), uuid.New()

	a := bus.Subscribe(ForTenant(tenantA))
	b := bus.Subscribe(ForTenant(tenantB))
	node := bus.Subscribe(ForNode(tenantA, "net-a"))
	otherNode := bus.Subscribe(ForNode(tenantB, "net-b"))
	edge := bus.Subscribe(Global())

	bus.Publish(Scope{TenantID: tenantA, NetworkID: "net-a"}, "node_joined", map[string]string{"k": "v"})

	if _, ok := recv(t, a); !ok {
		t.Fatal("tenant A should see its own event")
	}
	if _, ok := recv(t, node); !ok {
		t.Fatal("node in net-a should see its network's event")
	}
	if _, ok := recv(t, edge); !ok {
		t.Fatal("global edge should see every event")
	}
	if _, ok := recv(t, b); ok {
		t.Fatal("tenant B must not see tenant A's event")
	}
	if _, ok := recv(t, otherNode); ok {
		t.Fatal("node in net-b must not see net-a's event")
	}

	// A zero-value scope (unauthenticated) sees nothing, even unscoped events.
	none := bus.Subscribe(Scope{})
	bus.Publish(Scope{}, "edge_registered", nil)
	if _, ok := recv(t, none); ok {
		t.Fatal("unauthenticated subscriber must fail closed")
	}
}

func TestBusDropsSlowSubscriber(t *testing.T) {
	bus := NewBus()
	slow := bus.Subscribe(Global())
	fast := bus.Subscribe(Global())

	for i := 0; i < subscriberBuffer+1; i++ {
		bus.Publish(Scope{}, "tick", i)
		// drain fast so only `slow` overflows
		<-fast.C
	}

	if bus.Len() != 1 {
		t.Fatalf("expected slow subscriber to be dropped, %d remain", bus.Len())
	}
	for range slow.C { // channel must be closed after buffered messages
	}
	slow.Close() // idempotent
	fast.Close()
}
