package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load with empty path failed: %v", err)
	}

	if cfg.ControlPlane.ListenAddr != ":8443" {
		t.Fatalf("expected default ListenAddr :8443, got %s", cfg.ControlPlane.ListenAddr)
	}
	if cfg.ControlPlane.DefaultCIDRv4 != "100.64.0.0/10" {
		t.Fatalf("expected default CIDRv4 100.64.0.0/10, got %s", cfg.ControlPlane.DefaultCIDRv4)
	}
	if cfg.Node.MTU != 1420 {
		t.Fatalf("expected default Node MTU 1420, got %d", cfg.Node.MTU)
	}
	if cfg.Edge.PoPCode != "KH" {
		t.Fatalf("expected default PoPCode KH, got %s", cfg.Edge.PoPCode)
	}
	if cfg.Gateway.Strategy != "latency" {
		t.Fatalf("expected default Gateway Strategy latency, got %s", cfg.Gateway.Strategy)
	}
}

func TestConfigEnvOverrides(t *testing.T) {
	_ = os.Setenv("ZRO_MODE", "edge")
	_ = os.Setenv("ZRO_EDGE_POP_CODE", "SG")
	_ = os.Setenv("ZRO_NODE_INTERFACE_MODE", "netstack")
	defer func() {
		_ = os.Unsetenv("ZRO_MODE")
		_ = os.Unsetenv("ZRO_EDGE_POP_CODE")
		_ = os.Unsetenv("ZRO_NODE_INTERFACE_MODE")
	}()

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Mode != "edge" {
		t.Fatalf("expected Mode overridden to edge, got %s", cfg.Mode)
	}
	if cfg.Edge.PoPCode != "SG" {
		t.Fatalf("expected Edge.PoPCode overridden to SG, got %s", cfg.Edge.PoPCode)
	}
	if cfg.Node.InterfaceMode != "netstack" {
		t.Fatalf("expected Node.InterfaceMode overridden to netstack, got %s", cfg.Node.InterfaceMode)
	}
}

func TestConfigFileLoading(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "test-zro.yaml")

	yamlContent := `
mode: plane
log_level: debug
control_plane:
  listen_addr: ":8888"
  public_url: "https://custom.zro.internal"
  secret_key: "custom-secret-key-test"
  require_auth: true
  edge_api_key: "edge-test-key"
`
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write test yaml: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load with config file failed: %v", err)
	}

	if cfg.Mode != "plane" {
		t.Fatalf("expected mode plane, got %s", cfg.Mode)
	}
	if cfg.ControlPlane.ListenAddr != ":8888" {
		t.Fatalf("expected listen_addr :8888, got %s", cfg.ControlPlane.ListenAddr)
	}
	if cfg.ControlPlane.PublicURL != "https://custom.zro.internal" {
		t.Fatalf("expected public_url https://custom.zro.internal, got %s", cfg.ControlPlane.PublicURL)
	}
	if !cfg.ControlPlane.RequireAuth {
		t.Fatalf("expected require_auth true")
	}
	if cfg.ControlPlane.EdgeAPIKey != "edge-test-key" {
		t.Fatalf("expected edge_api_key edge-test-key, got %s", cfg.ControlPlane.EdgeAPIKey)
	}

	// Test non-existent file
	_, err = Load(filepath.Join(tmpDir, "non-existent.yaml"))
	if err == nil {
		t.Fatalf("expected error for non-existent config file")
	}
}
