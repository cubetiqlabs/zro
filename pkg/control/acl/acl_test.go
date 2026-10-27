package acl

import (
	"testing"

	"github.com/cubetiqlabs/zro/pkg/core"
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
			ID:       uuid.New(),
			Priority: 3,
			SourceIP: "100.64.0.11",
			DestIP:   "100.64.0.10",
			Protocol: "tcp",
			Ports:    "5432",
			Action:   core.ACLActionAllow,
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
	if !eval.CanAccessWithIP("", []string{"tag:web"}, "", []string{"tag:db"}, "tcp", 5432) {
		t.Fatalf("expected web to access db on 5432 TCP")
	}

	// Case 2: Web -> DB on port 22 (SSH) -> DENY
	if eval.CanAccessWithIP("", []string{"tag:web"}, "", []string{"tag:db"}, "tcp", 22) {
		t.Fatalf("expected web NOT to access db on port 22")
	}

	// Case 3: Admin -> Any on any port -> ALLOW
	if !eval.CanAccessWithIP("", []string{"tag:admin"}, "", []string{"tag:db"}, "tcp", 22) {
		t.Fatalf("expected admin to access anything")
	}

	// Case 4: Stranger -> Any -> DENY (hits rule 100)
	if eval.CanAccessWithIP("", []string{"tag:guest"}, "", []string{"tag:web"}, "tcp", 80) {
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

func TestPortAllowed(t *testing.T) {
	allowed := []string{"5432/tcp", "8000-8100/tcp", "53"}
	for _, c := range []struct {
		proto string
		port  int
		want  bool
	}{{"tcp", 5432, true}, {"udp", 5432, false}, {"tcp", 8050, true}, {"udp", 53, true}, {"tcp", 22, false}} {
		if got := PortAllowed(allowed, c.proto, c.port); got != c.want {
			t.Errorf("%s/%d: got %v", c.proto, c.port, got)
		}
	}
}

func BenchmarkDecide(b *testing.B) {
	rules := make([]core.ACLRule, 0, 20)
	for i := 0; i < 19; i++ {
		rules = append(rules, core.ACLRule{Priority: i, SourceIP: "10.0.0.0/8", SourceTag: "tag:x", DestTag: "*", Protocol: "tcp", Ports: "1000-2000", Action: core.ACLActionAllow})
	}
	rules = append(rules, core.ACLRule{Priority: 100, SourceIP: "100.64.0.0/10", SourceTag: "*", DestTag: "*", Protocol: "tcp", Ports: "22,443", Action: core.ACLActionAllow})
	eval := NewEvaluator(rules)
	b.ReportAllocs()
	for b.Loop() {
		eval.Decide("100.64.0.9", nil, "100.64.0.2", nil, "tcp", 443)
	}
}

func TestPriorityOrderDenyTieBreakAndStrictIPs(t *testing.T) {
	// Listed out of order: the lower priority number must win regardless.
	rules := []core.ACLRule{
		{Priority: 50, SourceTag: "*", DestTag: "*", Protocol: "*", Ports: "22", Action: core.ACLActionAllow},
		{Priority: 10, SourceTag: "tag:contractor", DestTag: "*", Protocol: "*", Ports: "22", Action: core.ACLActionDeny},
		{Priority: 70, SourceTag: "*", DestTag: "*", Protocol: "tcp", Ports: "80", Action: core.ACLActionAllow},
		{Priority: 70, SourceTag: "*", DestTag: "*", Protocol: "tcp", Ports: "80", Action: core.ACLActionDeny},
	}
	e := NewEvaluator(rules)

	if allow, matched := e.Decide("", []string{"tag:contractor"}, "", nil, "tcp", 22); !matched || allow {
		t.Fatalf("the priority-10 DENY must beat the priority-50 ALLOW, got allow=%v matched=%v", allow, matched)
	}
	if allow, matched := e.Decide("", []string{"tag:staff"}, "", nil, "tcp", 22); !matched || !allow {
		t.Fatalf("others reach 22 through the ALLOW, got allow=%v matched=%v", allow, matched)
	}
	if allow, matched := e.Decide("", nil, "", nil, "tcp", 80); !matched || allow {
		t.Fatalf("equal priority: DENY must win, got allow=%v matched=%v", allow, matched)
	}
	if _, matched := e.Decide("", nil, "", nil, "tcp", 9999); matched {
		t.Fatal("no rule covers 9999, the caller falls back to its own policy")
	}
	if rules[0].Priority != 50 {
		t.Fatal("the caller's slice must not be reordered")
	}

	// A rule naming an address must not match when the address is unknown.
	named := NewEvaluator([]core.ACLRule{{Priority: 1, SourceIP: "100.64.0.11", DestTag: "*", SourceTag: "*", Protocol: "*", Ports: "*", Action: core.ACLActionAllow}})
	if _, matched := named.Decide("", nil, "", nil, "tcp", 1); matched {
		t.Fatal("an unknown source must not satisfy a rule that names an IP")
	}
	if allow, matched := named.Decide("100.64.0.11", nil, "", nil, "tcp", 1); !matched || !allow {
		t.Fatal("the named source must match")
	}
}

func TestValidateRule(t *testing.T) {
	ok := core.ACLRule{SourceIP: "100.64.0.0/10", DestIP: "*", Protocol: "tcp", Ports: "80,443,8000-8080", Action: core.ACLActionAllow}
	if err := ValidateRule(&ok); err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
	bad := []core.ACLRule{
		{SourceIP: "100.64.0.0/99", Ports: "*", Protocol: "*", Action: core.ACLActionAllow},
		{DestIP: "not-an-ip", Ports: "*", Protocol: "*", Action: core.ACLActionAllow},
		{Ports: "80,abc", Protocol: "*", Action: core.ACLActionAllow},
		{Ports: "9000-8000", Protocol: "*", Action: core.ACLActionAllow},
		{Ports: "70000", Protocol: "*", Action: core.ACLActionAllow},
		{Ports: "*", Protocol: "gre", Action: core.ACLActionAllow},
		{Ports: "*", Protocol: "*", Action: "MAYBE"},
	}
	for i := range bad {
		if err := ValidateRule(&bad[i]); err == nil {
			t.Errorf("bad rule %d accepted: %+v", i, bad[i])
		}
	}
}
