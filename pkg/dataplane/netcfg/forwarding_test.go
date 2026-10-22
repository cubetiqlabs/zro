package netcfg

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnableForwarding(t *testing.T) {
	dir := t.TempDir()
	on := filepath.Join(dir, "on")
	off := filepath.Join(dir, "off")
	_ = os.WriteFile(on, []byte("1\n"), 0o444) // read-only but already enabled
	_ = os.WriteFile(off, []byte("0\n"), 0o644)

	if err := enableForwarding([]string{on, off}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(off); string(b) != "1\n" {
		t.Fatalf("off not enabled: %q", b)
	}
	if err := enableForwarding([]string{filepath.Join(dir, "missing", "x")}); err == nil {
		t.Fatal("want error for unwritable path")
	}
}
