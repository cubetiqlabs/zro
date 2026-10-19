package store

import (
	"fmt"
	"log/slog"
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
	Tenants  core.TenantRepository
	Networks core.NetworkRepository
	EdgePoPs core.EdgePoPRepository
	Nodes    core.NodeRepository
	ACLs     core.ACLRepository
	Routes   core.RouteRepository
	Tunnels  core.TunnelRepository
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
		Logger: logger.Default.LogMode(logger.Silent),
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

	// Execute schema auto-migrations
	if err := gormDB.AutoMigrate(
		&core.Tenant{},
		&core.Network{},
		&core.EdgePoP{},
		&core.Node{},
		&core.ACLRule{},
		&core.Route{},
		&core.Tunnel{},
	); err != nil {
		return nil, fmt.Errorf("failed to auto-migrate database schema: %w", err)
	}

	slog.Info("Database schema migrated successfully", "driver", driverName)

	dbInstance := &DB{
		DB:       gormDB,
		Tenants:  newTenantRepo(gormDB),
		Networks: newNetworkRepo(gormDB),
		EdgePoPs: newEdgePoPRepo(gormDB),
		Nodes:    newNodeRepo(gormDB),
		ACLs:     newACLRepo(gormDB),
		Routes:   newRouteRepo(gormDB),
		Tunnels:  newTunnelRepo(gormDB),
	}

	return dbInstance, nil
}
