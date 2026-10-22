package node

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/cubetiqlabs/zro/pkg/config"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/google/uuid"
)

// newMeshNode starts a netstack-mode node with an overlay address, bound to an
// ephemeral loopback-reachable UDP port.
func newMeshNode(t *testing.T, name, ip string, cfg config.NodeConfig) *Daemon {
	t.Helper()
	cfg.Hostname, cfg.InterfaceName, cfg.MTU, cfg.InterfaceMode = name, "zro-"+name, 1420, "netstack"
	d, err := NewDaemon(&cfg)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	t.Cleanup(func() { _ = d.Stop() })
	d.nodeID = uuid.New()
	if err := d.AssignOverlay(ip, ""); err != nil {
		t.Fatalf("assign overlay for %s: %v", name, err)
	}
	return d
}

func linkNodes(t *testing.T, a, b *Daemon) {
	t.Helper()
	pa := core.Node{PublicKey: a.PublicKey(), OverlayIPv4: a.OverlayIPv4(), Hostname: a.cfg.Hostname}
	pb := core.Node{PublicKey: b.PublicKey(), OverlayIPv4: b.OverlayIPv4(), Hostname: b.cfg.Hostname}
	// The responder first, so it already knows the initiator when the handshake arrives.
	if err := b.AddDirectPeer(pa, fmt.Sprintf("127.0.0.1:%d", a.UDPPort()), false); err != nil {
		t.Fatal(err)
	}
	if err := a.AddDirectPeer(pb, fmt.Sprintf("127.0.0.1:%d", b.UDPPort()), true); err != nil {
		t.Fatal(err)
	}
	// Dial only once the session is up: a SYN sent earlier would be lost and TCP
	// retransmits back off exponentially.
	deadline := time.Now().Add(15 * time.Second)
	for !a.PeerHandshaken(b.PublicKey()) {
		if time.Now().After(deadline) {
			t.Fatal("WireGuard handshake between the nodes never completed")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestNodeZeroTrustInterconnection runs real TCP between two nodes over a real
// WireGuard session (netstack on both ends, loopback UDP underneath) and checks
// the inbound zero-trust policy against it.
func TestNodeZeroTrustInterconnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	node1 := newMeshNode(t, "db", "100.64.0.10", config.NodeConfig{DefaultDeny: true, AllowedInboundPorts: []string{"5432/tcp"}})
	node2 := newMeshNode(t, "app", "100.64.0.11", config.NodeConfig{DefaultDeny: true})
	linkNodes(t, node1, node2)

	serve := func(port int) {
		ln, err := node1.ListenMesh(ctx, "tcp", port)
		if err != nil {
			t.Fatalf("listen %d: %v", port, err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					buf := make([]byte, 64)
					n, _ := c.Read(buf)
					if string(buf[:n]) == "SELECT 1;" {
						_, _ = c.Write([]byte("1\n"))
					}
				}()
			}
		}()
	}
	serve(5432)
	serve(22)

	query := func(port int) (string, error) {
		conn, err := node2.DialMesh(ctx, "tcp", fmt.Sprintf("100.64.0.10:%d", port))
		if err != nil {
			return "", err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write([]byte("SELECT 1;")); err != nil {
			return "", err
		}
		buf := make([]byte, 16)
		n, err := conn.Read(buf)
		return string(buf[:n]), err
	}

	// A: the allowed port answers.
	if got, err := query(5432); err != nil || got != "1\n" {
		t.Fatalf("allowed port 5432: got %q, err %v", got, err)
	}
	// B: an unlisted port is cut off by the destination's default-deny.
	if got, err := query(22); err == nil {
		t.Fatalf("port 22 must be blocked under default deny, got %q", got)
	}
	// C: opening the port at runtime takes effect immediately.
	node1.AllowPort("22/tcp")
	if got, err := query(22); err != nil || got != "1\n" {
		t.Fatalf("port 22 after AllowPort: got %q, err %v", got, err)
	}
}

// TestTunnelProxiesOverlayToLocalService exposes a loopback-only service on the
// overlay and reaches it from another node.
func TestTunnelProxiesOverlayToLocalService(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	go func() {
		for {
			c, err := local.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	localAddr := local.Addr().String()

	server := newMeshNode(t, "svc", "100.64.0.20", config.NodeConfig{DefaultDeny: true})
	client := newMeshNode(t, "gw", "100.64.0.21", config.NodeConfig{DefaultDeny: true})
	linkNodes(t, server, client)

	// The overlay port equals the local service's port, as the gateway expects.
	_, portStr, _ := net.SplitHostPort(localAddr)
	port, _ := strconv.Atoi(portStr)
	if err := server.ExposeTunnel(ctx, localAddr); err != nil {
		t.Fatal(err)
	}

	conn, err := client.DialMesh(ctx, "tcp", fmt.Sprintf("100.64.0.20:%d", port))
	if err != nil {
		t.Fatalf("dial tunnel over the overlay: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("through-the-tunnel")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := io.ReadFull(conn, buf[:len("through-the-tunnel")])
	if err != nil || string(buf[:n]) != "through-the-tunnel" {
		t.Fatalf("echo through tunnel failed: %q %v", buf[:n], err)
	}
}

// TestNetworkPolicyOverridesLocalFirewall: central rules close ports the node
// opens, open ports the node's default-deny closes, and fall back to the local
// firewall when no rule matches.
func TestNetworkPolicyOverridesLocalFirewall(t *testing.T) {
	d := newMeshNode(t, "pol", "100.64.0.40", config.NodeConfig{
		DefaultDeny: true, AllowedInboundPorts: []string{"5432/tcp"}, Tags: []string{"tag:db"},
	})
	d.peers["k-web"] = core.Node{PublicKey: "k-web", OverlayIPv4: "100.64.0.41", Tags: core.StringList{"tag:web"}}
	d.peers["k-con"] = core.Node{PublicKey: "k-con", OverlayIPv4: "100.64.0.42", Tags: core.StringList{"tag:contractor"}}

	// No central policy: the local firewall alone decides.
	if !d.IsTrafficAllowed("100.64.0.41", "tcp", 5432) || d.IsTrafficAllowed("100.64.0.41", "tcp", 8080) {
		t.Fatal("without a network policy the local allow-list applies")
	}

	d.policy.setRules([]core.ACLRule{
		{Priority: 10, SourceTag: "tag:contractor", DestTag: "*", SourceIP: "*", DestIP: "*", Protocol: "*", Ports: "*", Action: core.ACLActionDeny},
		{Priority: 20, SourceTag: "tag:web", DestTag: "tag:db", SourceIP: "*", DestIP: "*", Protocol: "tcp", Ports: "8080", Action: core.ACLActionAllow},
	})

	if d.IsTrafficAllowed("100.64.0.42", "tcp", 5432) {
		t.Fatal("a central DENY must close a port the node opened locally")
	}
	if !d.IsTrafficAllowed("100.64.0.41", "tcp", 8080) {
		t.Fatal("a central ALLOW must open a port the node's default-deny closed")
	}
	if !d.IsTrafficAllowed("100.64.0.41", "tcp", 5432) {
		t.Fatal("traffic no rule matches falls back to the local allow-list")
	}
	if d.IsTrafficAllowed("100.64.0.41", "tcp", 9999) {
		t.Fatal("unmatched and not locally allowed must stay denied")
	}
	if d.IsTrafficAllowed("100.64.0.99", "tcp", 8080) {
		t.Fatal("an unknown source has no tags, so the web rule must not open the port")
	}

	d.policy.setRules(nil) // rules removed: back to the local firewall only
	if d.IsTrafficAllowed("100.64.0.41", "tcp", 8080) {
		t.Fatal("removing the policy must close what it opened")
	}
}

func TestSOCKSProxyIsLoopbackAndOverlayOnly(t *testing.T) {
	d := newMeshNode(t, "sx", "100.64.0.50", config.NodeConfig{DefaultDeny: true})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Destinations outside the overlay (the host's own network, names) are refused.
	for _, target := range []string{"127.0.0.1:22", "10.0.0.5:80", "example.com:443"} {
		if conn, err := d.dialOverlayOnly(ctx, "tcp", target); err == nil {
			conn.Close()
			t.Fatalf("%s must not be reachable through the proxy", target)
		}
	}

	// Without authentication it may only listen on loopback.
	d.cfg.SOCKSListen = "0.0.0.0:0"
	if err := d.startSOCKS(); err == nil {
		t.Fatal("a non-loopback SOCKS listener must be refused")
	}
	d.cfg.SOCKSListen = "127.0.0.1:0"
	if err := d.startSOCKS(); err != nil {
		t.Fatalf("loopback listener: %v", err)
	}
}
