//go:build linux || darwin

package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"os/user"
	"strings"
	"testing"

	"github.com/cubetiqlabs/zro/pkg/config"
	"github.com/cubetiqlabs/zro/pkg/core"
	"golang.org/x/crypto/ssh"
)

func TestBuiltinSSH(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	newKey := func() ssh.Signer {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		s, _ := ssh.NewSignerFromKey(priv)
		return s
	}
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	peerKey, strangerKey := newKey(), newKey()

	// The client connects from 127.0.0.1, which the peer list gives to "admin-1".
	d := &Daemon{
		httpClient: http.DefaultClient, // audit reports go to a closed port
		cfg:        &config.NodeConfig{PlaneEndpoint: "http://127.0.0.1:1", SSH: config.SSHConfig{Enabled: true, Allow: []config.SSHGrant{{From: "tag:admin", Users: []string{me.Username}}}}},
		sshKey:     hostPriv,
		peers: map[string]core.Node{"k": {
			Hostname: "admin-1", OverlayIPv4: "127.0.0.1", Tags: core.StringList{"tag:admin"},
			SSHKey: string(ssh.MarshalAuthorizedKey(peerKey.PublicKey())),
		}},
	}
	cfg := &ssh.ServerConfig{PublicKeyCallback: d.sshAuth}
	cfg.AddHostKey(d.sshSigner())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go d.serveSSHConn(context.Background(), c, cfg)
		}
	}()

	dial := func(username string, key ssh.Signer) (*ssh.Client, error) {
		return ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
			User: username, Auth: []ssh.AuthMethod{ssh.PublicKeys(key)},
			HostKeyCallback: ssh.FixedHostKey(d.sshSigner().PublicKey()),
		})
	}

	client, err := dial(me.Username, peerKey)
	if err != nil {
		t.Fatalf("peer with its own key: %v", err)
	}
	defer client.Close()
	s, _ := client.NewSession()
	var out bytes.Buffer
	s.Stdout = &out
	err = s.Run("echo hi; exit 3")
	var exit *ssh.ExitError
	if !errors.As(err, &exit) || exit.ExitStatus() != 3 || strings.TrimSpace(out.String()) != "hi" {
		t.Fatalf("exec: out=%q err=%v", out.String(), err)
	}
	if s, _ := client.NewSession(); s.RequestSubsystem("sftp") == nil {
		t.Error("sftp subsystem accepted")
	}
	if _, err := client.Dial("tcp", "127.0.0.1:1"); err == nil {
		t.Error("port forwarding accepted")
	}

	if _, err := dial(me.Username, strangerKey); err == nil {
		t.Error("a key that is not the peer's was accepted")
	}
	if _, err := dial("root", peerKey); err == nil && me.Username != "root" {
		t.Error("a user without a grant was accepted")
	}
	d.cfg.SSH.Allow[0].From = "tag:other"
	if _, err := dial(me.Username, peerKey); err == nil {
		t.Error("a peer without a matching grant was accepted")
	}
}
