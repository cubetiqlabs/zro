package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cubis/zro/pkg/config"
	"github.com/cubis/zro/pkg/control/server"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/crypto"
	"github.com/cubis/zro/pkg/node"
	"github.com/cubis/zro/pkg/store"
)

// A restarted node keeps its key, node ID and overlay address, and a copy of its
// enrollment token cannot take the node over from elsewhere.
func TestNodeRestartKeepsIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	const secret = "restart-secret"
	db, err := store.NewDB("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	plane := server.NewServer(&config.ControlPlaneConfig{SecretKey: secret, DefaultCIDRv4: "100.64.0.0/16", DefaultCIDRv6: "fd00:cafe::/64"}, db)
	ts := httptest.NewServer(plane.Handler())
	defer ts.Close()

	body, _ := json.Marshal(server.CreateNetworkRequest{Name: "r"})
	resp, err := http.Post(ts.URL+"/api/v1/networks", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("create network: %v", err)
	}
	var network core.Network
	_ = json.NewDecoder(resp.Body).Decode(&network)
	resp.Body.Close()

	state := t.TempDir()
	token := crypto.GenerateEnrollmentToken(secret, network.ID, "durable", time.Hour) // unbound: lives in config
	cfg := func() *config.NodeConfig {
		return &config.NodeConfig{
			Hostname: "durable", InterfaceName: "zro-e2e-rs", InterfaceMode: "netstack", MTU: 1420,
			PlaneEndpoint: ts.URL, EnrollmentToken: token, StateDir: state,
		}
	}
	run := func() (id, ip, pub string) {
		d, err := node.NewDaemon(cfg())
		if err != nil {
			t.Fatal(err)
		}
		if err := d.Start(ctx); err != nil {
			t.Fatalf("start: %v", err)
		}
		id, ip, pub = d.NodeID().String(), d.OverlayIPv4(), d.PublicKey()
		_ = d.Stop()
		return
	}

	id1, ip1, pub1 := run()
	id2, ip2, pub2 := run() // restart: same state dir, same token
	if id1 != id2 || ip1 != ip2 || pub1 != pub2 {
		t.Fatalf("identity changed across a restart: %s/%s/%s -> %s/%s/%s", id1, ip1, pub1, id2, ip2, pub2)
	}
	if nodes, _ := db.Nodes.ListByNetworkID(ctx, network.ID); len(nodes) != 1 {
		t.Fatalf("a restart must not leave extra nodes, found %d", len(nodes))
	}

	// Someone with only the leaked token and the victim's public key (visible to
	// every peer) cannot take the node over: no node token, no re-enrollment.
	takeover, _ := json.Marshal(server.EnrollRequest{Token: token, PublicKey: pub1, Hostname: "durable"})
	resp, err = http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(takeover))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("token + public key alone must not re-enroll an existing node, got %d", resp.StatusCode)
	}
}

// Once the enrollment token has expired, a node holding its saved node token
// still rejoins; a node without that state does not.
func TestNodeResumesAfterEnrollmentTokenExpires(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	const secret = "resume-secret"
	db, err := store.NewDB("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	plane := server.NewServer(&config.ControlPlaneConfig{SecretKey: secret, DefaultCIDRv4: "100.64.0.0/16", DefaultCIDRv6: "fd00:cafe::/64"}, db)
	ts := httptest.NewServer(plane.Handler())
	defer ts.Close()

	body, _ := json.Marshal(server.CreateNetworkRequest{Name: "r"})
	resp, err := http.Post(ts.URL+"/api/v1/networks", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("create network: %v", err)
	}
	var network core.Network
	_ = json.NewDecoder(resp.Body).Decode(&network)
	resp.Body.Close()

	state := t.TempDir()
	start := func(dir, token string) (*node.Daemon, error) {
		d, err := node.NewDaemon(&config.NodeConfig{
			Hostname: "resume", InterfaceName: "zro-e2e-rm", InterfaceMode: "netstack", MTU: 1420,
			PlaneEndpoint: ts.URL, EnrollmentToken: token, StateDir: dir,
		})
		if err != nil {
			t.Fatal(err)
		}
		return d, d.Start(ctx)
	}

	d, err := start(state, crypto.GenerateEnrollmentToken(secret, network.ID, "resume", time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	id := d.NodeID()
	_ = d.Stop()

	expired := crypto.GenerateEnrollmentToken(secret, network.ID, "resume", -time.Minute)
	d, err = start(state, expired)
	if err != nil {
		t.Fatalf("a node with saved state must rejoin on an expired enrollment token: %v", err)
	}
	if d.NodeID() != id {
		t.Fatalf("node ID changed on resume: %s -> %s", id, d.NodeID())
	}
	_ = d.Stop()

	// No saved node token: the expired enrollment token is rightly refused.
	if d, err := start(t.TempDir(), expired); err == nil {
		_ = d.Stop()
		t.Fatal("an expired enrollment token must not enroll a fresh node")
	}
}
