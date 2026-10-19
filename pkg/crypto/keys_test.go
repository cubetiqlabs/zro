package crypto

import (
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
