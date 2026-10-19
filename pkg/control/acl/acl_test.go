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
}
