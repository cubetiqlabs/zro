package store

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/cubis/zro/pkg/core"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB wraps the GORM database instance and repositories.
type DB struct {
	*gorm.DB
	Tenants     core.TenantRepository
	Networks    core.NetworkRepository
	EdgePoPs    core.EdgePoPRepository
	Nodes       core.NodeRepository
	ACLs        core.ACLRepository
	Tunnels     core.TunnelRepository
	Enrollments core.EnrollmentRepository
}

// NewDB opens a database connection (PostgreSQL or SQLite) and executes auto-migrations.
func NewDB(driverName, dsn string) (*DB, error) {
	var dialector gorm.Dialector

	switch driverName {
	case "postgres":
		dialector = postgres.Open(dsn)
	case "sqlite":
		dialector = sqlite.Open(dsn)
	default:
		return nil, fmt.Errorf("unsupported database driver %q (supported: 'postgres', 'sqlite')", driverName)
	}

	gormDB, err := gorm.Open(dialector, &gorm.Config{
		Logger:         logger.Default.LogMode(logger.Silent),
		TranslateError: true, // surface unique violations as gorm.ErrDuplicatedKey
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := gormDB.DB()
	if err == nil {
		sqlDB.SetMaxIdleConns(10)
		sqlDB.SetMaxOpenConns(100)
		sqlDB.SetConnMaxLifetime(time.Hour)
	}

	if err := dedupeNodes(gormDB); err != nil {
		return nil, fmt.Errorf("failed to prepare node uniqueness: %w", err)
	}

	// Execute schema auto-migrations
	if err := gormDB.AutoMigrate(
		&core.Tenant{},
		&core.Network{},
		&core.EdgePoP{},
		&core.Node{},
		&core.ACLRule{},
		&core.Tunnel{},
		&core.EnrollmentRedemption{},
	); err != nil {
		return nil, fmt.Errorf("failed to auto-migrate database schema: %w", err)
	}

	// Drop legacy UNIQUE index on tunnels(public_hostname) if present to allow multi-node clustering
	_ = gormDB.Exec("DROP INDEX IF EXISTS idx_tunnels_public_hostname").Error
	_ = gormDB.Exec("CREATE INDEX IF NOT EXISTS idx_tunnels_public_hostname ON tunnels(public_hostname)").Error

	// Hash any tenant API keys stored in plaintext by older versions.
	var legacy []core.Tenant
	if err := gormDB.Find(&legacy).Error; err == nil {
		for _, t := range legacy {
			if len(t.APIKey) != 64 || strings.Trim(t.APIKey, "0123456789abcdef") != "" {
				gormDB.Model(&core.Tenant{}).Where("id = ?", t.ID).Update("api_key", core.HashAPIKey(t.APIKey))
			}
		}
	}

	// Backfill tenant/network ownership on tunnels created before they carried it.
	_ = gormDB.Exec(`UPDATE tunnels SET network_id = (SELECT network_id FROM nodes WHERE nodes.id = tunnels.node_id)
		WHERE (network_id IS NULL OR network_id = '')`).Error
	_ = gormDB.Exec(`UPDATE tunnels SET tenant_id = (SELECT tenant_id FROM networks WHERE networks.id = tunnels.network_id)
		WHERE tenant_id IS NULL OR tenant_id = '00000000-0000-0000-0000-000000000000'`).Error

	slog.Info("Database schema migrated successfully", "driver", driverName)

	dbInstance := &DB{
		DB:          gormDB,
		Tenants:     newTenantRepo(gormDB),
		Networks:    newNetworkRepo(gormDB),
		EdgePoPs:    newEdgePoPRepo(gormDB),
		Nodes:       newNodeRepo(gormDB),
		ACLs:        newACLRepo(gormDB),
		Tunnels:     newTunnelRepo(gormDB),
		Enrollments: newEnrollmentRepo(gormDB),
	}

	return dbInstance, nil
}

// dedupeNodes removes duplicate node rows left behind by earlier versions
// (every restart enrolled a fresh node) so the unique indexes on
// (network_id, public_key) and (network_id, overlay_ipv4) can be created. The
// most recently seen row of each group survives.
func dedupeNodes(db *gorm.DB) error {
	if !db.Migrator().HasTable(&core.Node{}) {
		return nil
	}
	for _, col := range []string{"public_key", "overlay_ipv4"} {
		err := db.Exec(`DELETE FROM nodes WHERE id IN (
			SELECT id FROM (
				SELECT id, ROW_NUMBER() OVER (PARTITION BY network_id, ` + col + ` ORDER BY last_seen_at DESC, created_at DESC) AS rn FROM nodes
			) ranked WHERE rn > 1)`).Error
		if err != nil {
			return err
		}
	}
	return nil
}
