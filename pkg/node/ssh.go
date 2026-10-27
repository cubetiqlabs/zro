package node

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cubetiqlabs/zro/pkg/core"
	"golang.org/x/crypto/ssh"
)

// The built-in SSH server. A peer gets a shell only when:
//   - the network policy lets it reach the SSH port (the packet filter),
//   - it signs with the SSH key the plane distributed for its own overlay
//     address, so a hijacked address or a relay cannot log in, and
//   - a grant in ssh.allow names the local user for that peer.
// Port forwarding, agent forwarding and subsystems (sftp) are refused.

var errSSHDenied = errors.New("permission denied")

func (d *Daemon) sshSigner() ssh.Signer {
	s, _ := ssh.NewSignerFromKey(d.sshKey) // ed25519 keys always convert
	return s
}

// sshPublicKey is the node's SSH key in authorized_keys format.
func (d *Daemon) sshPublicKey() string {
	if d.sshKey == nil {
		return ""
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(d.sshSigner().PublicKey())))
}

// sshPort is the advertised SSH port; 0 when the server is off.
func (d *Daemon) sshPort() int {
	if !d.cfg.SSH.Enabled {
		return 0
	}
	return d.cfg.SSH.Port
}

// SignSSH signs data with the node's SSH key, for `zro ssh` on this machine.
func (d *Daemon) SignSSH(data []byte) (*ssh.Signature, error) {
	return d.sshSigner().Sign(nil, data)
}

func (d *Daemon) peerByIP(ip string) (core.Node, bool) {
	d.peersMu.RLock()
	defer d.peersMu.RUnlock()
	for _, p := range d.peers {
		if p.OverlayIPv4 == ip || p.OverlayIPv6 == ip {
			return p, true
		}
	}
	return core.Node{}, false
}

// sshUsersFor lists the local accounts peer may log in as.
func (d *Daemon) sshUsersFor(peer core.Node) []string {
	var users []string
	for _, g := range d.cfg.SSH.Allow {
		if g.From == "*" || g.From == peer.Hostname || g.From == peer.OverlayIPv4 || slices.Contains(peer.Tags, g.From) {
			users = append(users, g.Users...)
		}
	}
	return users
}

// sshAuth checks the client key against the one the plane holds for the peer
// at the connection's source address.
func (d *Daemon) sshAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	src := remoteIP(conn.RemoteAddr())
	peer, ok := d.peerByIP(src)
	if !ok || peer.SSHKey == "" {
		return nil, errSSHDenied
	}
	want, _, _, _, err := ssh.ParseAuthorizedKey([]byte(peer.SSHKey))
	if err != nil || !bytes.Equal(want.Marshal(), key.Marshal()) {
		slog.Warn("SSH login refused: key does not belong to the peer at this address", "src", src, "user", conn.User())
		return nil, errSSHDenied
	}
	if !slices.Contains(d.sshUsersFor(peer), conn.User()) {
		slog.Warn("SSH login refused: no ssh.allow grant for this user", "peer", peer.Hostname, "user", conn.User())
		return nil, errSSHDenied
	}
	return &ssh.Permissions{Extensions: map[string]string{"peer": peer.Hostname}}, nil
}

func remoteIP(a net.Addr) string {
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap().String()
	}
	host, _, _ := net.SplitHostPort(a.String())
	return host
}

// startSSH listens on the overlay address. Port 22 is often held by the
// host's own sshd; the error then says to pick another ssh.port.
func (d *Daemon) startSSH(ctx context.Context) {
	if !d.cfg.SSH.Enabled {
		return
	}
	if len(d.cfg.SSH.Allow) == 0 {
		slog.Warn("SSH is enabled but ssh.allow grants no one; every login will be refused")
	}
	port := d.cfg.SSH.Port
	d.AllowPort(fmt.Sprintf("%d/tcp", port))
	ln, err := d.dev.Net.Listen(port)
	if err != nil {
		slog.Error("Built-in SSH server could not listen; if the host's sshd uses this port, set ssh.port (e.g. 2222)", "port", port, "error", err)
		return
	}
	cfg := &ssh.ServerConfig{PublicKeyCallback: d.sshAuth, ServerVersion: "SSH-2.0-zro"}
	cfg.AddHostKey(d.sshSigner())
	slog.Info("Built-in SSH server listening on the mesh", "address", net.JoinHostPort(d.overlayIPv4, fmt.Sprint(port)))

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		go func() { <-ctx.Done(); _ = ln.Close() }()
		sem := make(chan struct{}, max(d.cfg.SSH.MaxSessions, 1))
		var conns sync.WaitGroup
		defer conns.Wait()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case sem <- struct{}{}:
			default:
				_ = c.Close() // at the session limit
				continue
			}
			conns.Add(1)
			go func() {
				defer conns.Done()
				defer func() { <-sem }()
				d.serveSSHConn(ctx, idleConn{Conn: c, idle: d.cfg.SSH.IdleTimeout}, cfg)
			}()
		}
	}()
}

func (d *Daemon) serveSSHConn(ctx context.Context, c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second)) // handshake must finish
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	defer sc.Close()
	go ssh.DiscardRequests(reqs) // global requests: tcpip-forward and friends are refused

	peer, user := sc.Permissions.Extensions["peer"], sc.User()
	slog.Info("SSH login", "peer", peer, "user", user)
	d.auditPlane("ssh.login", user, "from "+peer+" ("+remoteIP(sc.RemoteAddr())+")")
	start := time.Now()
	defer func() {
		d.auditPlane("ssh.logout", user, fmt.Sprintf("from %s after %s", peer, time.Since(start).Round(time.Second)))
	}()

	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.Prohibited, "only sessions are allowed")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go d.serveSession(ctx, ch, chReqs, user)
	}
}

// idleConn closes a connection that receives nothing for idle.
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c idleConn) Read(b []byte) (int, error) {
	if c.idle > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	}
	return c.Conn.Read(b)
}

// auditPlane reports an event to the plane's audit log, best effort.
func (d *Daemon) auditPlane(action, target, detail string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		body := map[string]string{"action": action, "target": target, "detail": detail}
		if err := d.postPlane(ctx, "/api/v1/node/audit", body, 201, nil); err != nil {
			slog.Debug("Could not report audit event", "action", action, "error", err)
		}
	}()
}
