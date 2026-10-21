package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKeyPersistsAcrossLoads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	a, err := LoadOrCreateKey(dir, "node.key")
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateKey(dir, "node.key")
	if err != nil {
		t.Fatal(err)
	}
	if a.PublicKey != b.PublicKey || a.PrivateKey != b.PrivateKey {
		t.Fatal("a restart must keep the same key")
	}
	info, _ := os.Stat(filepath.Join(dir, "node.key"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file must be 0600, got %o", info.Mode().Perm())
	}
}

func TestEphemeralWithoutDir(t *testing.T) {
	a, _ := LoadOrCreateKey("", "x")
	b, _ := LoadOrCreateKey("", "x")
	if a.PublicKey == b.PublicKey {
		t.Fatal("no state dir means a fresh key each time")
	}
}

func TestRefusesLooseKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreateKey(dir, "k"); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(filepath.Join(dir, "k"), 0o644)
	if _, err := LoadOrCreateKey(dir, "k"); err == nil {
		t.Fatal("a group/world readable private key must be rejected")
	}
}
