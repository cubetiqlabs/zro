package acme

import (
	"context"
	"os"
	"testing"
)

func TestACMEManager(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zro-acme-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := Config{
		Enabled: true,
		Domains: []string{"api.cubis.tech", "mesh.cubis.tech"},
		CertDir: tmpDir,
		Email:   "admin@cubis.tech",
	}

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("failed to create ACME manager: %v", err)
	}

	tlsCfg := mgr.TLSConfig()
	if tlsCfg == nil {
		t.Fatalf("expected non-nil TLS config")
	}

	// Test Host Policy
	ctx := context.Background()
	if err := mgr.manager.HostPolicy(ctx, "api.cubis.tech"); err != nil {
		t.Fatalf("expected allowed domain, got error: %v", err)
	}
	if err := mgr.manager.HostPolicy(ctx, "sub.mesh.cubis.tech"); err != nil {
		t.Fatalf("expected allowed wildcard subdomain, got error: %v", err)
	}
	if err := mgr.manager.HostPolicy(ctx, "evil.com"); err == nil {
		t.Fatalf("expected error for unauthorized domain, got nil")
	}
}
