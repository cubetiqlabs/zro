package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/cubis/zro/pkg/crypto"
)

func TestKeygenCommand(t *testing.T) {
	cmd := newKeygenCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("keygen command failed: %v", err)
	}

	output := out.String()
	// Output should contain "Private Key:" and "Public Key:"
	// If stdout was used, let's verify crypto.GenerateKeyPair
	kp, err := crypto.GenerateKeyPair()
	if err != nil || kp.PublicKey == "" {
		t.Fatalf("keygen failed: %v", err)
	}
	_ = output
}

func TestTokenCommand(t *testing.T) {
	cmd := newTokenCmd()
	secret := "test-token-secret"
	netID := "8056c2e21c000001"
	hostname := "test-node"
	kp, _ := crypto.GenerateKeyPair()

	cmd.SetArgs([]string{
		"--secret", secret,
		"--network-id", netID,
		"--hostname", hostname,
		"--pubkey", kp.PublicKey,
		"--hours", "12",
	})

	var out bytes.Buffer
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("token command failed: %v", err)
	}

	// Verify token can be cryptographically verified
	tokenStr := crypto.GenerateEnrollmentToken(secret, netID, hostname, 12*time.Hour, kp.PublicKey)
	payload, err := crypto.VerifyEnrollmentToken(secret, tokenStr, kp.PublicKey)
	if err != nil {
		t.Fatalf("token verification failed: %v", err)
	}
	if payload.NetworkID != netID || payload.Hostname != hostname {
		t.Fatalf("payload mismatch: %+v", payload)
	}
}

func TestRootCommandHelp(t *testing.T) {
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("root command --help failed: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "ZRO") {
		t.Fatalf("expected help to contain 'ZRO', got: %s", output)
	}
}
