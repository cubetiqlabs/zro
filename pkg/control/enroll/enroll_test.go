package enroll

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/crypto"
	"github.com/cubis/zro/pkg/store"
)

func TestAuthorize(t *testing.T) {
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	const secret = "enroll-test-secret"
	ctx := context.Background()
	kp, _ := crypto.GenerateKeyPair()
	other, _ := crypto.GenerateKeyPair()
	mint := func(host, nodeType string) string {
		tok, err := crypto.SignEnrollmentToken(secret, crypto.EnrollmentTokenPayload{
			NetworkID: "net", Hostname: host, NodeType: nodeType, Expiry: time.Now().Add(time.Minute).Unix(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}

	if _, err := Authorize(ctx, secret, db.Enrollments, Request{Token: mint("h", ""), PublicKey: ""}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("empty public key must be rejected, got %v", err)
	}
	if _, err := Authorize(ctx, secret, db.Enrollments, Request{Token: mint("h", ""), PublicKey: kp.PublicKey, Hostname: "evil"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("hostname mismatch must be forbidden, got %v", err)
	}
	if _, err := Authorize(ctx, secret, db.Enrollments, Request{Token: mint("h", ""), PublicKey: kp.PublicKey, NodeType: core.NodeTypeGateway}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("a peer token must not enroll a gateway, got %v", err)
	}

	tok := mint("h", "gateway")
	grant, err := Authorize(ctx, secret, db.Enrollments, Request{Token: tok, PublicKey: kp.PublicKey})
	if err != nil || grant.NodeType != core.NodeTypeGateway || grant.Hostname != "h" {
		t.Fatalf("unexpected grant %+v err=%v", grant, err)
	}
	if _, err := Authorize(ctx, secret, db.Enrollments, Request{Token: tok, PublicKey: other.PublicKey}); !errors.Is(err, ErrConflict) {
		t.Fatalf("replay by a different key must conflict, got %v", err)
	}
}
