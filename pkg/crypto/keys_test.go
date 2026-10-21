package crypto

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateAndDeriveKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if kp.PrivateKey == "" || kp.PublicKey == "" {
		t.Fatalf("expected non-empty keys, got priv=%s, pub=%s", kp.PrivateKey, kp.PublicKey)
	}

	derivedPub, err := DerivePublicKey(kp.PrivateKey)
	if err != nil {
		t.Fatalf("DerivePublicKey failed: %v", err)
	}

	if derivedPub != kp.PublicKey {
		t.Fatalf("derived public key mismatch: expected %s, got %s", kp.PublicKey, derivedPub)
	}
}

func TestEnrollmentTokens(t *testing.T) {
	secret := "super-secure-cluster-secret-key"
	networkID := "b7c2512a-7c2a-4864-b767-a4d45850cd15"
	hostname := "node-kh-01"

	token := GenerateEnrollmentToken(secret, networkID, hostname, 5*time.Minute)
	payload, err := VerifyEnrollmentToken(secret, token)
	if err != nil {
		t.Fatalf("token verification failed: %v", err)
	}

	if payload.NetworkID != networkID || payload.Hostname != hostname {
		t.Fatalf("payload mismatch: %+v", payload)
	}

	// Test invalid secret
	_, err = VerifyEnrollmentToken("wrong-secret", token)
	if err == nil {
		t.Fatalf("expected error with wrong secret, got nil")
	}

	// Test expired token
	expiredToken := GenerateEnrollmentToken(secret, networkID, hostname, -1*time.Minute)
	_, err = VerifyEnrollmentToken(secret, expiredToken)
	if err == nil {
		t.Fatalf("expected error for expired token, got nil")
	}
}

func TestEnrollmentTokenClaims(t *testing.T) {
	const secret = "claims-test-secret"
	exp := time.Now().Add(time.Minute).Unix()

	tok, err := SignEnrollmentToken(secret, EnrollmentTokenPayload{
		NetworkID: "net", Hostname: "gw", NodeType: "gateway", BoundPublicKey: "pk", Expiry: exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := VerifyEnrollmentToken(secret, tok, "pk")
	if err != nil || p.NodeType != "gateway" || p.Nonce == "" {
		t.Fatalf("unexpected payload %+v err=%v", p, err)
	}

	// A bound token must not verify when the caller omits or changes the key.
	if _, err := VerifyEnrollmentToken(secret, tok); err == nil {
		t.Fatal("bound token accepted without a public key")
	}
	if _, err := VerifyEnrollmentToken(secret, tok, "other"); err == nil {
		t.Fatal("bound token accepted for the wrong public key")
	}

	// Tampering with the claims invalidates the signature.
	forged := strings.Replace(tok, tok[len(enrollmentTokenPrefix):len(enrollmentTokenPrefix)+4], "AAAA", 1)
	if _, err := VerifyEnrollmentToken(secret, forged, "pk"); err == nil {
		t.Fatal("tampered token accepted")
	}

	// Every token gets a fresh nonce.
	a := GenerateEnrollmentToken(secret, "net", "h", time.Minute)
	b := GenerateEnrollmentToken(secret, "net", "h", time.Minute)
	pa, _ := VerifyEnrollmentToken(secret, a)
	pb, _ := VerifyEnrollmentToken(secret, b)
	if pa.Nonce == pb.Nonce {
		t.Fatal("nonce reused across tokens")
	}
}
