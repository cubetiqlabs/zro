package store

import (
	"context"
	"errors"

	"github.com/cubis/zro/pkg/core"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// --- Tenant Repository ---

type tenantRepo struct {
	db *gorm.DB
}

func newTenantRepo(db *gorm.DB) core.TenantRepository {
	return &tenantRepo{db: db}
}

func (r *tenantRepo) Create(ctx context.Context, tenant *core.Tenant) error {
	return r.db.WithContext(ctx).Create(tenant).Error
}

func (r *tenantRepo) GetByID(ctx context.Context, id uuid.UUID) (*core.Tenant, error) {
	var t core.Tenant
	if err := r.db.WithContext(ctx).Preload("Networks").First(&t, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *tenantRepo) GetByAPIKey(ctx context.Context, apiKey string) (*core.Tenant, error) {
	var t core.Tenant
	if err := r.db.WithContext(ctx).First(&t, "api_key = ?", apiKey).Error; err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *tenantRepo) List(ctx context.Context) ([]core.Tenant, error) {
	var tenants []core.Tenant
	err := r.db.WithContext(ctx).Find(&tenants).Error
	return tenants, err
}

func (r *tenantRepo) Update(ctx context.Context, tenant *core.Tenant) error {
	return r.db.WithContext(ctx).Save(tenant).Error
}

func (r *tenantRepo) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&core.Tenant{}, "id = ?", id).Error
}

// --- Network Repository ---

type networkRepo struct {
	db *gorm.DB
}

func newNetworkRepo(db *gorm.DB) core.NetworkRepository {
	return &networkRepo{db: db}
}

func (r *networkRepo) Create(ctx context.Context, network *core.Network) error {
	return r.db.WithContext(ctx).Create(network).Error
}

func (r *networkRepo) GetByID(ctx context.Context, id uuid.UUID) (*core.Network, error) {
	var net core.Network
	if err := r.db.WithContext(ctx).Preload("Nodes").Preload("ACLRules").Preload("Routes").First(&net, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &net, nil
}

func (r *networkRepo) ListByTenantID(ctx context.Context, tenantID uuid.UUID) ([]core.Network, error) {
	var networks []core.Network
	err := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID).Find(&networks).Error
	return networks, err
}

func (r *networkRepo) Update(ctx context.Context, network *core.Network) error {
	return r.db.WithContext(ctx).Save(network).Error
}

func (r *networkRepo) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&core.Network{}, "id = ?", id).Error
}

// --- EdgePoP Repository ---

type edgePoPRepo struct {
	db *gorm.DB
}

func newEdgePoPRepo(db *gorm.DB) core.EdgePoPRepository {
	return &edgePoPRepo{db: db}
}

func (r *edgePoPRepo) Create(ctx context.Context, pop *core.EdgePoP) error {
	return r.db.WithContext(ctx).Create(pop).Error
}

func (r *edgePoPRepo) GetByID(ctx context.Context, id uuid.UUID) (*core.EdgePoP, error) {
	var pop core.EdgePoP
	if err := r.db.WithContext(ctx).First(&pop, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &pop, nil
}

func (r *edgePoPRepo) GetByPoPCode(ctx context.Context, code string) (*core.EdgePoP, error) {
	var pop core.EdgePoP
	if err := r.db.WithContext(ctx).First(&pop, "pop_code = ?", code).Error; err != nil {
		return nil, err
	}
	return &pop, nil
}

func (r *edgePoPRepo) ListHealthy(ctx context.Context) ([]core.EdgePoP, error) {
	var pops []core.EdgePoP
	err := r.db.WithContext(ctx).Where("is_healthy = ?", true).Order("weight desc").Find(&pops).Error
	return pops, err
}

func (r *edgePoPRepo) ListAll(ctx context.Context) ([]core.EdgePoP, error) {
	var pops []core.EdgePoP
	err := r.db.WithContext(ctx).Order("pop_code asc").Find(&pops).Error
	return pops, err
}

func (r *edgePoPRepo) Update(ctx context.Context, pop *core.EdgePoP) error {
	return r.db.WithContext(ctx).Save(pop).Error
}

func (r *edgePoPRepo) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&core.EdgePoP{}, "id = ?", id).Error
}

// --- Node Repository ---

type nodeRepo struct {
	db *gorm.DB
}

func newNodeRepo(db *gorm.DB) core.NodeRepository {
	return &nodeRepo{db: db}
}

func (r *nodeRepo) Create(ctx context.Context, node *core.Node) error {
	return r.db.WithContext(ctx).Create(node).Error
}

func (r *nodeRepo) GetByID(ctx context.Context, id uuid.UUID) (*core.Node, error) {
	var node core.Node
	if err := r.db.WithContext(ctx).Preload("AssignedPoP").Preload("Tunnels").First(&node, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &node, nil
}

func (r *nodeRepo) GetByPublicKey(ctx context.Context, pubKey string) (*core.Node, error) {
	var node core.Node
	if err := r.db.WithContext(ctx).Preload("AssignedPoP").First(&node, "public_key = ?", pubKey).Error; err != nil {
		return nil, err
	}
	return &node, nil
}

func (r *nodeRepo) ListByNetworkID(ctx context.Context, networkID uuid.UUID) ([]core.Node, error) {
	var nodes []core.Node
	err := r.db.WithContext(ctx).Preload("AssignedPoP").Where("network_id = ?", networkID).Find(&nodes).Error
	return nodes, err
}

func (r *nodeRepo) ListActiveByPoPID(ctx context.Context, popID uuid.UUID) ([]core.Node, error) {
	var nodes []core.Node
	err := r.db.WithContext(ctx).Where("assigned_pop_id = ? AND is_active = ?", popID, true).Find(&nodes).Error
	return nodes, err
}

func (r *nodeRepo) Update(ctx context.Context, node *core.Node) error {
	return r.db.WithContext(ctx).Save(node).Error
}

func (r *nodeRepo) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&core.Node{}, "id = ?", id).Error
}

func (r *nodeRepo) ListAllocatedIPs(ctx context.Context, networkID uuid.UUID) ([]string, error) {
	var ips []string
	err := r.db.WithContext(ctx).Model(&core.Node{}).Where("network_id = ?", networkID).Pluck("overlay_ipv4", &ips).Error
	return ips, err
}

// --- ACL Repository ---

type aclRepo struct {
	db *gorm.DB
}

func newACLRepo(db *gorm.DB) core.ACLRepository {
	return &aclRepo{db: db}
}

func (r *aclRepo) Create(ctx context.Context, rule *core.ACLRule) error {
	return r.db.WithContext(ctx).Create(rule).Error
}

func (r *aclRepo) GetByID(ctx context.Context, id uuid.UUID) (*core.ACLRule, error) {
	var rule core.ACLRule
	if err := r.db.WithContext(ctx).First(&rule, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &rule, nil
}

func (r *aclRepo) ListByNetworkID(ctx context.Context, networkID uuid.UUID) ([]core.ACLRule, error) {
	var rules []core.ACLRule
	err := r.db.WithContext(ctx).Where("network_id = ?", networkID).Order("priority asc").Find(&rules).Error
	return rules, err
}

func (r *aclRepo) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&core.ACLRule{}, "id = ?", id).Error
}

// --- Route Repository ---

type routeRepo struct {
	db *gorm.DB
}

func newRouteRepo(db *gorm.DB) core.RouteRepository {
	return &routeRepo{db: db}
}

func (r *routeRepo) Create(ctx context.Context, route *core.Route) error {
	return r.db.WithContext(ctx).Create(route).Error
}

func (r *routeRepo) GetByID(ctx context.Context, id uuid.UUID) (*core.Route, error) {
	var route core.Route
	if err := r.db.WithContext(ctx).First(&route, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &route, nil
}

func (r *routeRepo) ListByNetworkID(ctx context.Context, networkID uuid.UUID) ([]core.Route, error) {
	var routes []core.Route
	err := r.db.WithContext(ctx).Where("network_id = ?", networkID).Find(&routes).Error
	return routes, err
}

func (r *routeRepo) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&core.Route{}, "id = ?", id).Error
}

// --- Tunnel Repository ---

type tunnelRepo struct {
	db *gorm.DB
}

func newTunnelRepo(db *gorm.DB) core.TunnelRepository {
	return &tunnelRepo{db: db}
}

func (r *tunnelRepo) Create(ctx context.Context, tunnel *core.Tunnel) error {
	return r.db.WithContext(ctx).Create(tunnel).Error
}

func (r *tunnelRepo) GetByID(ctx context.Context, id uuid.UUID) (*core.Tunnel, error) {
	var tunnel core.Tunnel
	if err := r.db.WithContext(ctx).First(&tunnel, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &tunnel, nil
}

func (r *tunnelRepo) GetByHostname(ctx context.Context, hostname string) (*core.Tunnel, error) {
	var tunnel core.Tunnel
	if err := r.db.WithContext(ctx).First(&tunnel, "public_hostname = ?", hostname).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &tunnel, nil
}

func (r *tunnelRepo) ListByNodeID(ctx context.Context, nodeID uuid.UUID) ([]core.Tunnel, error) {
	var tunnels []core.Tunnel
	err := r.db.WithContext(ctx).Where("node_id = ?", nodeID).Find(&tunnels).Error
	return tunnels, err
}

func (r *tunnelRepo) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&core.Tunnel{}, "id = ?", id).Error
}
