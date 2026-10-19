package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	KeySize = 32
)

// KeyPair represents a WireGuard Curve25519 keypair in base64.
type KeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// GenerateKeyPair generates a new WireGuard-compatible Curve25519 keypair.
func GenerateKeyPair() (*KeyPair, error) {
	var priv [KeySize]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, fmt.Errorf("failed to read random bytes: %w", err)
	}

	// Clamp the private key as per Curve25519 / RFC 7748
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to compute public key: %w", err)
	}

	return &KeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(priv[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// DerivePublicKey computes the WireGuard public key from a base64 private key.
func DerivePublicKey(privateKeyBase64 string) (string, error) {
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privateKeyBase64))
	if err != nil {
		return "", fmt.Errorf("invalid base64 private key: %w", err)
	}
	if len(priv) != KeySize {
		return "", fmt.Errorf("invalid private key length: expected %d bytes, got %d", KeySize, len(priv))
	}

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("failed to compute public key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(pub), nil
}

// GeneratePresharedKey generates a 32-byte pre-shared key (PSK) in base64.
func GeneratePresharedKey() (string, error) {
	var psk [KeySize]byte
	if _, err := rand.Read(psk[:]); err != nil {
		return "", fmt.Errorf("failed to generate random psk: %w", err)
	}
	return base64.StdEncoding.EncodeToString(psk[:]), nil
}

// GenerateRandomHex returns a cryptographically secure random hex string of n bytes.
func GenerateRandomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// EnrollmentTokenPayload carries node enrollment claims.
type EnrollmentTokenPayload struct {
	NetworkID      string
	Hostname       string
	ExpiresAt      time.Time
	BoundPublicKey string
}

// GenerateEnrollmentToken creates a signed, time-bound node enrollment token, optionally bound to a WireGuard public key.
func GenerateEnrollmentToken(secretKey string, networkID, hostname string, duration time.Duration, boundPubKey ...string) string {
	exp := time.Now().Add(duration).Unix()
	var pubKey string
	if len(boundPubKey) > 0 {
		pubKey = boundPubKey[0]
	}

	payload := fmt.Sprintf("%s:%s:%d:%s", networkID, hostname, exp, pubKey)
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return fmt.Sprintf("zro_tok_%s.%s", encodedPayload, sig)
}

// VerifyEnrollmentToken validates a signed node enrollment token and checks public key binding if bound.
func VerifyEnrollmentToken(secretKey, token string, clientPubKey ...string) (*EnrollmentTokenPayload, error) {
	if !strings.HasPrefix(token, "zro_tok_") {
		return nil, errors.New("invalid token format")
	}
	parts := strings.Split(strings.TrimPrefix(token, "zro_tok_"), ".")
	if len(parts) != 2 {
		return nil, errors.New("malformed token structure")
	}

	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("failed to decode token payload")
	}

	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write(rawPayload)
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return nil, errors.New("invalid token signature")
	}

	subParts := strings.Split(string(rawPayload), ":")
	if len(subParts) < 3 {
		return nil, errors.New("invalid payload elements")
	}

	var expSec int64
	if _, err := fmt.Sscanf(subParts[2], "%d", &expSec); err != nil {
		return nil, errors.New("invalid token expiration")
	}

	exp := time.Unix(expSec, 0)
	if time.Now().After(exp) {
		return nil, errors.New("token expired")
	}

	var boundKey string
	if len(subParts) >= 4 {
		boundKey = subParts[3]
	}

	// If token was bound to a specific WireGuard public key, enforce match
	if boundKey != "" && len(clientPubKey) > 0 && clientPubKey[0] != "" {
		if boundKey != clientPubKey[0] {
			return nil, fmt.Errorf("token bound to public key %s, received %s", boundKey, clientPubKey[0])
		}
	}

	return &EnrollmentTokenPayload{
		NetworkID:      subParts[0],
		Hostname:       subParts[1],
		ExpiresAt:      exp,
		BoundPublicKey: boundKey,
	}, nil
}
