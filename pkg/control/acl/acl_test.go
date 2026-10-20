package acl

import (
	"testing"

	"github.com/cubis/zro/pkg/core"
	"github.com/google/uuid"
)

func TestACLEvaluator(t *testing.T) {
	rules := []core.ACLRule{
		{
			ID:        uuid.New(),
			Priority:  1,
			SourceTag: "tag:web",
			DestTag:   "tag:db",
			Protocol:  "tcp",
			Ports:     "5432",
			Action:    core.ACLActionAllow,
		},
		{
			ID:        uuid.New(),
			Priority:  2,
			SourceTag: "tag:admin",
			DestTag:   "*",
			Protocol:  "*",
			Ports:     "*",
			Action:    core.ACLActionAllow,
		},
		{
			ID:        uuid.New(),
			Priority:  3,
			SourceIP:  "100.64.0.11",
			DestIP:    "100.64.0.10",
			Protocol:  "tcp",
			Ports:     "5432",
			Action:    core.ACLActionAllow,
		},
		{
			ID:        uuid.New(),
			Priority:  100,
			SourceTag: "*",
			DestTag:   "*",
			Protocol:  "*",
			Ports:     "*",
			Action:    core.ACLActionDeny,
		},
	}

	eval := NewEvaluator(rules)

	// Case 1: Web -> DB on port 5432 (TCP) -> ALLOW
	if !eval.CanAccess([]string{"tag:web"}, []string{"tag:db"}, "tcp", 5432) {
		t.Fatalf("expected web to access db on 5432 TCP")
	}

	// Case 2: Web -> DB on port 22 (SSH) -> DENY
	if eval.CanAccess([]string{"tag:web"}, []string{"tag:db"}, "tcp", 22) {
		t.Fatalf("expected web NOT to access db on port 22")
	}

	// Case 3: Admin -> Any on any port -> ALLOW
	if !eval.CanAccess([]string{"tag:admin"}, []string{"tag:db"}, "tcp", 22) {
		t.Fatalf("expected admin to access anything")
	}

	// Case 4: Stranger -> Any -> DENY (hits rule 100)
	if eval.CanAccess([]string{"tag:guest"}, []string{"tag:web"}, "tcp", 80) {
		t.Fatalf("expected guest to be denied")
	}

	// Case 5: Direct IP matching (node2 100.64.0.11 -> node1 100.64.0.10:5432 TCP) -> ALLOW
	if !eval.CanAccessWithIP("100.64.0.11", nil, "100.64.0.10", nil, "tcp", 5432) {
		t.Fatalf("expected 100.64.0.11 to access 100.64.0.10 on 5432")
	}

	// Case 6: Direct IP matching unallowed port (100.64.0.11 -> 100.64.0.10:22) -> DENY
	if eval.CanAccessWithIP("100.64.0.11", nil, "100.64.0.10", nil, "tcp", 22) {
		t.Fatalf("expected 100.64.0.11 to be denied on port 22")
	}
}

func TestZeroTrustInboundFirewall(t *testing.T) {
	eval := NewEvaluator(nil)

	// Node 1 hosts Postgres server: allows port 5432/tcp, default deny all
	allowedPorts := []string{"5432/tcp"}
	defaultDeny := true

	// Scenario: Node 2 (100.64.0.11) connects to Node 1 on port 5432/tcp -> ALLOW
	if !eval.EvaluateInbound("100.64.0.11", []string{"tag:app"}, "tcp", 5432, allowedPorts, defaultDeny) {
		t.Fatalf("expected node 2 to be allowed on port 5432 (postgres)")
	}

	// Scenario: Node 2 connects to Node 1 on port 22 (ssh) -> DENY (default deny all)
	if eval.EvaluateInbound("100.64.0.11", []string{"tag:app"}, "tcp", 22, allowedPorts, defaultDeny) {
		t.Fatalf("expected node 2 to be DENIED on port 22 under zero-trust default deny")
	}

	// Scenario: Node 2 connects to Node 1 on port 80 (http) -> DENY (default deny all)
	if eval.EvaluateInbound("100.64.0.11", []string{"tag:app"}, "tcp", 80, allowedPorts, defaultDeny) {
		t.Fatalf("expected node 2 to be DENIED on port 80 under zero-trust default deny")
	}
}
