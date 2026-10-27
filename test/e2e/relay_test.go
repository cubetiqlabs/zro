// Package e2e wires the real control plane, an edge PoP and two nodes together
// in one process and moves bytes between the nodes through the edge.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cubetiqlabs/zro/pkg/config"
	"github.com/cubetiqlabs/zro/pkg/control/server"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/cubetiqlabs/zro/pkg/crypto"
	"github.com/cubetiqlabs/zro/pkg/edge"
	"github.com/cubetiqlabs/zro/pkg/node"
	"github.com/cubetiqlabs/zro/pkg/store"
)

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// TestNodeToNodeThroughEdge: node A -> edge PoP -> node B, over enrollment,
// PoP delegation, WireGuard, the edge's userspace forwarding and the overlay
// TCP stacks, with direct P2P disabled so the edge is the only path.
func TestNodeToNodeThroughEdge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const (
		secret  = "e2e-secret"
		edgeKey = "e2e-edge-key"
	)
	db, err := store.NewDB("sqlite", fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name()))
	if err != nil {
		t.Fatal(err)
	}
	plane := server.NewServer(&config.ControlPlaneConfig{
		SecretKey: secret, EdgeAPIKey: edgeKey, DefaultCIDRv4: "100.64.0.0/16", DefaultCIDRv6: "fd00:cafe::/64",
	}, db)
	ts := httptest.NewServer(plane.Handler())
	defer ts.Close()

	// Network (permissive mode owns it with the default tenant).
	body, _ := json.Marshal(server.CreateNetworkRequest{Name: "e2e"})
	resp, err := http.Post(ts.URL+"/api/v1/networks", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("create network: %v", err)
	}
	var network core.Network
	_ = json.NewDecoder(resp.Body).Decode(&network)
	resp.Body.Close()

	// Edge PoP.
	edgePort := freeUDPPort(t)
	e, err := edge.NewPoPDaemon(&config.EdgeConfig{
		PoPCode: "KH", Region: "test", PublicEndpoint: fmt.Sprintf("127.0.0.1:%d", edgePort), ListenPort: edgePort,
		InterfaceName: "zro-e2e-edge", MTU: 1420, PlaneEndpoint: ts.URL, EdgeAPIKey: edgeKey, StateDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	waitFor(t, 10*time.Second, "edge to register", func() bool {
		pops, _ := db.EdgePoPs.ListHealthy(ctx)
		return len(pops) == 1
	})

	// Two nodes; P2P is off so the edge must carry the traffic.
	start := func(name string, extra config.NodeConfig) *node.Daemon {
		extra.Hostname, extra.InterfaceName, extra.InterfaceMode, extra.MTU = name, "zro-e2e-"+name, "netstack", 1420
		extra.PlaneEndpoint = ts.URL
		extra.EnableP2P = false
		extra.EnrollmentToken = crypto.GenerateEnrollmentToken(secret, network.ID, name, time.Hour)
		d, err := node.NewDaemon(&extra)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.Start(ctx); err != nil {
			t.Fatalf("start %s: %v", name, err)
		}
		t.Cleanup(func() { _ = d.Stop() })
		return d
	}
	b := start("b", config.NodeConfig{DefaultDeny: true, AllowedInboundPorts: []string{"7000/tcp"}})
	a := start("a", config.NodeConfig{DefaultDeny: true})

	// Wait for each node's session with the edge before the first SYN: TCP
	// retransmits a lost SYN with exponential backoff.
	for _, d := range []*node.Daemon{a, b} {
		d := d
		waitFor(t, 30*time.Second, "node to complete its handshake with the edge", func() bool { return d.PeerHandshaken(e.PublicKey()) })
	}

	ln, err := b.ListenMesh(ctx, "tcp", 7000)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()

	// The edge learns each node from the plane (event or periodic sync), so the
	// first attempts may race it; retry until the path is up.
	target := net.JoinHostPort(b.OverlayIPv4(), "7000")
	var echoed string
	waitFor(t, 40*time.Second, "A to reach B through the edge", func() bool {
		dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		conn, err := a.DialMesh(dialCtx, "tcp", target)
		if err != nil {
			return false
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write([]byte("via-edge")); err != nil {
			return false
		}
		buf := make([]byte, 8)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return false
		}
		echoed = string(buf)
		return true
	})
	if echoed != "via-edge" {
		t.Fatalf("unexpected echo %q", echoed)
	}

	// Network-wide policy reaches the nodes live: a DENY rule created through the
	// API cuts the path that was just working, and deleting it restores it.
	reaches := func() bool {
		// The filter drops a denied SYN, so a blocked dial ends at its deadline.
		dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		conn, err := a.DialMesh(dialCtx, "tcp", target)
		if err != nil {
			return false
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte("probe!!!")); err != nil {
			return false
		}
		_, err = io.ReadFull(conn, make([]byte, 8))
		return err == nil
	}
	ruleBody, _ := json.Marshal(server.CreateACLRuleRequest{
		NetworkID: network.ID, Priority: 1, Ports: "7000", Protocol: "tcp", Action: core.ACLActionDeny,
	})
	resp, err = http.Post(ts.URL+"/api/v1/acl/rules", "application/json", bytes.NewReader(ruleBody))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("create deny rule: %v", err)
	}
	var rule core.ACLRule
	_ = json.NewDecoder(resp.Body).Decode(&rule)
	resp.Body.Close()
	waitFor(t, 15*time.Second, "the DENY rule to reach node B", func() bool { return !reaches() })

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/acl/rules/"+rule.ID.String(), nil)
	if resp, err = http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("delete rule: %v", err)
	}
	resp.Body.Close()
	waitFor(t, 15*time.Second, "the path to reopen after the rule was deleted", reaches)
}

func waitFor(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
