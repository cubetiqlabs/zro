package node

import (
	"slices"
	"testing"

	"github.com/cubetiqlabs/zro/pkg/config"
)

func TestLocalPolicyPersists(t *testing.T) {
	cfg := &config.NodeConfig{StateDir: t.TempDir(), Allow: []string{"https"}, AllowedInboundPorts: []string{"5432/tcp"}}
	d := &Daemon{cfg: cfg}
	if err := d.loadLocalPolicy(); err != nil {
		t.Fatal(err)
	}
	if err := d.AllowService("ssh"); err != nil {
		t.Fatal(err)
	}
	if !d.IsTrafficAllowed("100.64.0.9", "tcp", 22) {
		t.Fatal("ssh not open after zro allow")
	}

	// A restart keeps what was opened at runtime.
	d2 := &Daemon{cfg: cfg, defaultDeny: true}
	if err := d2.loadLocalPolicy(); err != nil {
		t.Fatal(err)
	}
	got := d2.localPolicy().Allow
	for _, want := range []string{"443/tcp", "5432/tcp", "22/tcp"} {
		if !slices.Contains(got, want) {
			t.Fatalf("after restart allow=%v, missing %s", got, want)
		}
	}
	if err := d2.DenyService("https"); err == nil {
		t.Fatal("a config entry was closed at runtime")
	}
	if err := d2.DenyService("22/tcp"); err != nil || d2.IsTrafficAllowed("100.64.0.9", "tcp", 22) {
		t.Fatalf("deny ssh: %v", err)
	}
	if err := d2.AllowService("telnet"); err == nil {
		t.Fatal("unknown service accepted")
	}
}
