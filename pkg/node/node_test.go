package node

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/cubis/zro/pkg/config"
	"github.com/google/uuid"
)

func TestNodeZeroTrustInterconnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Setup Node 1 (100.64.0.10) - hosting Postgres server on port 5432
	cfg1 := &config.NodeConfig{
		Hostname:            "node1-db",
		InterfaceName:       "zro-test1",
		MTU:                 1420,
		DefaultDeny:         true,
		AllowedInboundPorts: []string{"5432/tcp"},
	}
	node1, err := NewDaemon(cfg1)
	if err != nil {
		t.Fatalf("failed to create node1: %v", err)
	}
	defer node1.Stop()

	node1.nodeID = uuid.New()
	node1.overlayIPv4 = "100.64.0.10"

	// 2. Setup Node 2 (100.64.0.11) - client node
	cfg2 := &config.NodeConfig{
		Hostname:      "node2-app",
		InterfaceName: "zro-test2",
		MTU:           1420,
		DefaultDeny:   true,
	}
	node2, err := NewDaemon(cfg2)
	if err != nil {
		t.Fatalf("failed to create node2: %v", err)
	}
	defer node2.Stop()

	node2.nodeID = uuid.New()
	node2.overlayIPv4 = "100.64.0.11"

	// 3. Start mock PostgreSQL listener on Node 1 (port 5432)
	ln, err := node1.ListenMesh(ctx, "tcp", 5432)
	if err != nil {
		t.Fatalf("node1 failed to listen on mesh port 5432: %v", err)
	}
	defer ln.Close()

	// Run mock postgres server handler
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c io.ReadWriteCloser) {
				defer c.Close()
				buf := make([]byte, 128)
				n, _ := c.Read(buf)
				query := string(buf[:n])
				if query == "SELECT 1;" {
					_, _ = c.Write([]byte("1\n"))
				} else {
					_, _ = c.Write([]byte("OK\n"))
				}
			}(conn)
		}
	}()

	// 4. Test Case A: Node 2 connects to Node 1 on port 5432 (Postgres) -> MUST SUCCEED
	connAllowed, err := node2.DialMesh(ctx, "tcp", "100.64.0.10:5432")
	if err != nil {
		t.Fatalf("expected node2 to successfully connect to node1 on allowed port 5432, got: %v", err)
	}
	defer connAllowed.Close()

	_, err = connAllowed.Write([]byte("SELECT 1;"))
	if err != nil {
		t.Fatalf("failed to write query to postgres service: %v", err)
	}

	resBuf := make([]byte, 16)
	n, err := connAllowed.Read(resBuf)
	if err != nil {
		t.Fatalf("failed to read response from postgres service: %v", err)
	}
	if string(resBuf[:n]) != "1\n" {
		t.Fatalf("expected '1\\n', got %q", string(resBuf[:n]))
	}
	t.Log("✅ Test Case A Passed: Node 2 (100.64.0.11) queried Node 1 (100.64.0.10:5432) Postgres successfully over mesh")

	// 5. Test Case B: Node 2 attempts to connect to Node 1 on unallowed port 22 (SSH) -> MUST BE REJECTED
	// Node 1 creates another internal listener on 22 (e.g. ssh daemon) without allowing it in its inbound policy
	lnSSH, err := node1.ListenMesh(ctx, "tcp", 22)
	if err != nil {
		t.Fatalf("failed to create ssh listener: %v", err)
	}
	defer lnSSH.Close()

	connDenied, err := node2.DialMesh(ctx, "tcp", "100.64.0.10:22")
	if err == nil {
		defer connDenied.Close()
		t.Fatalf("expected connection to port 22 to be REJECTED under zero-trust default deny, but it succeeded")
	}
	t.Logf("✅ Test Case B Passed: Node 2 blocked on unallowed port 22: %v", err)

	// 6. Test Case C: Dynamically allow port 22 and verify connection now passes
	node1.AllowPort("22/tcp")
	connNowAllowed, err := node2.DialMesh(ctx, "tcp", "100.64.0.10:22")
	if err != nil {
		t.Fatalf("expected connection to port 22 to succeed after dynamic allow, got: %v", err)
	}
	_ = connNowAllowed.Close()
	t.Log("✅ Test Case C Passed: Dynamic firewall rule successfully allowed port 22")
}
