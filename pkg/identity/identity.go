// Package identity persists an agent's long-lived secrets (its WireGuard key
// and issued credentials) so a restart keeps the same mesh identity.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"

	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"strings"

	"github.com/cubetiqlabs/zro/pkg/crypto"
)

// DefaultDir is where agents keep state when state_dir is not configured:
// /var/lib/zro for root, otherwise a per-user directory.
func DefaultDir() string {
	if os.Geteuid() == 0 {
		return "/var/lib/zro"
	}
	if dir := os.Getenv("XDG_STATE_HOME"); dir != "" {
		return filepath.Join(dir, "zro")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "state", "zro")
	}
	return ""
}

// LoadOrCreateKey returns the WireGuard key pair stored as dir/name. A missing
// file is created with a fresh key (mode 0600). An empty dir yields an
// ephemeral key that is not persisted.
func LoadOrCreateKey(dir, name string) (*crypto.KeyPair, error) {
	if dir == "" {
		return crypto.GenerateKeyPair()
	}
	if priv, err := ReadSecret(dir, name); err == nil {
		pub, err := crypto.DerivePublicKey(priv)
		if err != nil {
			return nil, fmt.Errorf("%s: stored key is invalid: %w", filepath.Join(dir, name), err)
		}
		return &crypto.KeyPair{PrivateKey: priv, PublicKey: pub}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	if err := WriteSecret(dir, name, kp.PrivateKey); err != nil {
		return nil, err
	}
	return kp, nil
}

// ReadSecret reads dir/name. It refuses files readable by group or others, the
// way ssh does for private keys. A missing file satisfies os.ErrNotExist.
func ReadSecret(dir, name string) (string, error) {
	path := filepath.Join(dir, name)
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s has permissions %o; restrict it with chmod 600", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// WriteSecret atomically writes value to dir/name with mode 0600, creating dir
// (0700) if needed.
func WriteSecret(dir, name, value string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating state dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(value + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name))
}

// LoadOrCreateSSHKey returns the node's SSH key stored as dir/name, creating
// an ed25519 key on first use. An empty dir gives an ephemeral key.
func LoadOrCreateSSHKey(dir, name string) (ed25519.PrivateKey, error) {
	if dir == "" {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
	raw, err := ReadSecret(dir, name)
	if err == nil {
		key, err := ssh.ParseRawPrivateKey([]byte(raw + "\n"))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(dir, name), err)
		}
		priv, ok := key.(*ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s is not an ed25519 key", filepath.Join(dir, name))
		}
		return *priv, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "zro node")
	if err != nil {
		return nil, err
	}
	return priv, WriteSecret(dir, name, strings.TrimSpace(string(pem.EncodeToMemory(block))))
}
