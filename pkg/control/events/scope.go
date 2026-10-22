// Package events defines the scoping rules used by the control plane's SSE,
// WebSocket, and gRPC event fan-out. A subscription is scoped to a tenant, a
// network, or the whole control plane (edge infrastructure only).
package events

import (
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/google/uuid"
)

// Scope identifies which events a subscriber may receive.
type Scope struct {
	TenantID  uuid.UUID
	NetworkID string
	Global    bool
}

// Global returns a scope that can observe every event. Callers must only use
// this for trusted infrastructure principals such as edge PoPs.
func Global() Scope {
	return Scope{Global: true}
}

// ForNode returns the scope for a node principal.
func ForNode(tenantID uuid.UUID, networkID string) Scope {
	return Scope{TenantID: tenantID, NetworkID: networkID}
}

// OfNetwork returns the scope of events that belong to a network.
func OfNetwork(n *core.Network) Scope {
	return Scope{TenantID: n.TenantID, NetworkID: n.ID}
}

// ForTenant returns the scope for a tenant API principal.
func ForTenant(tenantID uuid.UUID) Scope {
	return Scope{TenantID: tenantID}
}

// Matches reports whether an event with the given scope is visible to the
// subscriber. Events without a tenant or network are treated as global
// control-plane events (for example edge PoP registration).
func (s Scope) Matches(event Scope) bool {
	if s.Global {
		return true
	}

	if s.NetworkID != "" {
		if event.NetworkID != "" {
			return event.NetworkID == s.NetworkID
		}
		// A network subscriber may see unscoped/global events, but not events
		// explicitly attributed to a different tenant.
		return event.TenantID == uuid.Nil || event.TenantID == s.TenantID
	}

	if s.TenantID != uuid.Nil {
		if event.TenantID != uuid.Nil {
			return event.TenantID == s.TenantID
		}
		// Fail closed when an event names a network but its tenant could not be
		// resolved. Only truly global events are visible.
		return event.NetworkID == ""
	}

	return false
}
