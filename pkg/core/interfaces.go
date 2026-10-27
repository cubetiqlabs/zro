package core

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// TenantRepository defines operations for Tenant entities.
type TenantRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*Tenant, error)
	// Create takes the plaintext APIKey, stores only its hash, and leaves the plaintext on the struct.
	Create(ctx context.Context, tenant *Tenant) error
	GetByAPIKey(ctx context.Context, apiKey string) (*Tenant, error)
	// RotateAPIKey replaces the tenant key with newKey (plaintext) and invalidates the old one.
	RotateAPIKey(ctx context.Context, id uuid.UUID, newKey string) error
	List(ctx context.Context) ([]Tenant, error)
	Update(ctx context.Context, tenant *Tenant) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// NetworkRepository defines operations for Network entities.
type NetworkRepository interface {
	Create(ctx context.Context, network *Network) error
	GetByID(ctx context.Context, id string) (*Network, error)
	ListByTenantID(ctx context.Context, tenantID uuid.UUID) ([]Network, error)
	Update(ctx context.Context, network *Network) error
	Delete(ctx context.Context, id string) error
}

// EdgePoPRepository defines operations for Edge PoPs.
type EdgePoPRepository interface {
	Create(ctx context.Context, pop *EdgePoP) error
	GetByID(ctx context.Context, id uuid.UUID) (*EdgePoP, error)
	GetByPoPCode(ctx context.Context, code string) (*EdgePoP, error)
	GetByKeyHash(ctx context.Context, keyHash string) (*EdgePoP, error)
	ListHealthy(ctx context.Context) ([]EdgePoP, error)
	ListAll(ctx context.Context) ([]EdgePoP, error)
	Update(ctx context.Context, pop *EdgePoP) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// NodeRepository defines operations for Nodes in the mesh.
type NodeRepository interface {
	Create(ctx context.Context, node *Node) error
	GetByID(ctx context.Context, id uuid.UUID) (*Node, error)
	GetByPublicKey(ctx context.Context, pubKey string) (*Node, error)
	GetByNetworkAndPublicKey(ctx context.Context, networkID, pubKey string) (*Node, error)
	GetByTokenHash(ctx context.Context, tokenHash string) (*Node, error)
	GetByOverlayIP(ctx context.Context, networkID string, overlayIP string) (*Node, error)
	ListByNetworkID(ctx context.Context, networkID string) ([]Node, error)
	ListActiveByPoPID(ctx context.Context, popID uuid.UUID) ([]Node, error)
	Update(ctx context.Context, node *Node) error
	Delete(ctx context.Context, id uuid.UUID) error
	ListAllocatedIPs(ctx context.Context, networkID string) ([]string, error)
	// TouchLastSeen records liveness without rewriting the whole row.
	TouchLastSeen(ctx context.Context, id uuid.UUID, at time.Time) error
	// ListStale returns nodes not seen since before, oldest first.
	ListStale(ctx context.Context, before time.Time, limit int) ([]Node, error)
	// ListExpiredBetween returns nodes whose key expired in (from, to].
	ListExpiredBetween(ctx context.Context, from, to time.Time) ([]Node, error)
}

// ACLRepository defines operations for Access Control Rules.
type ACLRepository interface {
	Create(ctx context.Context, rule *ACLRule) error
	GetByID(ctx context.Context, id uuid.UUID) (*ACLRule, error)
	ListByNetworkID(ctx context.Context, networkID string) ([]ACLRule, error)
	Update(ctx context.Context, rule *ACLRule) error
	// Replace makes rules the network's whole policy, atomically.
	Replace(ctx context.Context, networkID string, rules []ACLRule) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// TunnelRepository defines operations for Cloudflared-style exposed services.
type TunnelRepository interface {
	Create(ctx context.Context, tunnel *Tunnel) error
	GetByID(ctx context.Context, id uuid.UUID) (*Tunnel, error)
	GetByHostname(ctx context.Context, hostname string) (*Tunnel, error)
	ListByHostname(ctx context.Context, hostname string) ([]Tunnel, error)
	ListByNodeID(ctx context.Context, nodeID uuid.UUID) ([]Tunnel, error)
	ListByNetworkID(ctx context.Context, networkID string) ([]Tunnel, error)
	ListAll(ctx context.Context) ([]Tunnel, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// ErrTokenReused is returned when an enrollment token was already redeemed by another key.
// ErrDuplicate is returned when a create violates a unique constraint.
var ErrDuplicate = errors.New("duplicate record")

var ErrTokenReused = errors.New("enrollment token already used")

// AuditRepository stores the audit trail.
type AuditRepository interface {
	Create(ctx context.Context, ev *AuditEvent) error
	// List returns a tenant's events newest first, optionally for one network,
	// created before before (zero = now), at most limit.
	List(ctx context.Context, tenantID uuid.UUID, networkID string, before time.Time, limit int) ([]AuditEvent, error)
	// Purge deletes events older than cutoff.
	Purge(ctx context.Context, cutoff time.Time) error
}

// EnrollmentRepository tracks redeemed enrollment-token nonces.
type EnrollmentRepository interface {
	// Redeem records nonce for pubKey. Re-redeeming with the same key is
	// allowed (idempotent re-enroll); a different key gets ErrTokenReused.
	Redeem(ctx context.Context, nonce, pubKey string, expires time.Time) error
	// PurgeExpired deletes redemptions whose token has expired.
	PurgeExpired(ctx context.Context) error
}
