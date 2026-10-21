package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	NetworkID      string    `json:"net"`
	Hostname       string    `json:"host"`
	NodeType       string    `json:"nt,omitempty"` // empty means "peer"
	BoundPublicKey string    `json:"pk,omitempty"`
	Nonce          string    `json:"n"` // unique per token; the control plane redeems each nonce once
	ExpiresAt      time.Time `json:"-"`
	Expiry         int64     `json:"exp"`
}

// DefaultSecretKey is the well-known placeholder shipped in example configs.
// It must never sign production tokens.
const DefaultSecretKey = "change-me-in-production-cluster-secret"

const enrollmentTokenPrefix = "zro_tok_"

func signEnrollmentPayload(secretKey string, raw []byte) string {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil))
}

// SignEnrollmentToken signs the given claims. A nonce is generated when empty.
func SignEnrollmentToken(secretKey string, p EnrollmentTokenPayload) (string, error) {
	if p.Nonce == "" {
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			return "", err
		}
		p.Nonce = hex.EncodeToString(nonce)
	}
	if p.Expiry == 0 {
		return "", errors.New("token expiry is required")
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%s.%s", enrollmentTokenPrefix, base64.RawURLEncoding.EncodeToString(raw), signEnrollmentPayload(secretKey, raw)), nil
}

// GenerateEnrollmentToken creates a signed, time-bound peer enrollment token,
// optionally bound to a WireGuard public key.
func GenerateEnrollmentToken(secretKey string, networkID, hostname string, duration time.Duration, boundPubKey ...string) string {
	p := EnrollmentTokenPayload{NetworkID: networkID, Hostname: hostname, Expiry: time.Now().Add(duration).Unix()}
	if len(boundPubKey) > 0 {
		p.BoundPublicKey = boundPubKey[0]
	}
	tok, err := SignEnrollmentToken(secretKey, p)
	if err != nil { // only reachable if the system RNG fails
		panic(fmt.Sprintf("crypto: enrollment token signing failed: %v", err))
	}
	return tok
}

// VerifyEnrollmentToken validates a signed node enrollment token. If the token
// is bound to a public key, the caller must present exactly that key.
func VerifyEnrollmentToken(secretKey, token string, clientPubKey ...string) (*EnrollmentTokenPayload, error) {
	if !strings.HasPrefix(token, enrollmentTokenPrefix) {
		return nil, errors.New("invalid token format")
	}
	parts := strings.Split(strings.TrimPrefix(token, enrollmentTokenPrefix), ".")
	if len(parts) != 2 {
		return nil, errors.New("malformed token structure")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("failed to decode token payload")
	}
	if !hmac.Equal([]byte(parts[1]), []byte(signEnrollmentPayload(secretKey, raw))) {
		return nil, errors.New("invalid token signature")
	}

	var p EnrollmentTokenPayload
	if err := json.Unmarshal(raw, &p); err != nil || p.NetworkID == "" || p.Nonce == "" {
		return nil, errors.New("invalid payload elements")
	}
	p.ExpiresAt = time.Unix(p.Expiry, 0)
	if time.Now().After(p.ExpiresAt) {
		return nil, errors.New("token expired")
	}
	if p.BoundPublicKey != "" && (len(clientPubKey) == 0 || clientPubKey[0] != p.BoundPublicKey) {
		return nil, errors.New("token is bound to a different public key")
	}
	return &p, nil
}

// ValidatePublicKey requires a base64-encoded 32-byte WireGuard key.
func ValidatePublicKey(key string) error {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != KeySize {
		return errors.New("public key must be a base64-encoded 32-byte key")
	}
	return nil
}
