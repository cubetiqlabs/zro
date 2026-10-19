package core

import (
	"context"

	"github.com/google/uuid"
)

// TenantRepository defines operations for Tenant entities.
type TenantRepository interface {
	Create(ctx context.Context, tenant *Tenant) error
	GetByID(ctx context.Context, id uuid.UUID) (*Tenant, error)
	GetByAPIKey(ctx context.Context, apiKey string) (*Tenant, error)
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
	ListByNetworkID(ctx context.Context, networkID string) ([]Node, error)
	ListActiveByPoPID(ctx context.Context, popID uuid.UUID) ([]Node, error)
	Update(ctx context.Context, node *Node) error
	Delete(ctx context.Context, id uuid.UUID) error
	ListAllocatedIPs(ctx context.Context, networkID string) ([]string, error)
}

// ACLRepository defines operations for Access Control Rules.
type ACLRepository interface {
	Create(ctx context.Context, rule *ACLRule) error
	GetByID(ctx context.Context, id uuid.UUID) (*ACLRule, error)
	ListByNetworkID(ctx context.Context, networkID string) ([]ACLRule, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// RouteRepository defines operations for subnet routes.
type RouteRepository interface {
	Create(ctx context.Context, route *Route) error
	GetByID(ctx context.Context, id uuid.UUID) (*Route, error)
	ListByNetworkID(ctx context.Context, networkID string) ([]Route, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// TunnelRepository defines operations for Cloudflared-style exposed services.
type TunnelRepository interface {
	Create(ctx context.Context, tunnel *Tunnel) error
	GetByID(ctx context.Context, id uuid.UUID) (*Tunnel, error)
	GetByHostname(ctx context.Context, hostname string) (*Tunnel, error)
	ListByNodeID(ctx context.Context, nodeID uuid.UUID) ([]Tunnel, error)
	Delete(ctx context.Context, id uuid.UUID) error
}
