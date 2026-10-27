package node

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/cubetiqlabs/zro/pkg/agent"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/cubetiqlabs/zro/pkg/dataplane/wireguard"
	"github.com/google/uuid"
)

// ListenMesh accepts overlay TCP connections on port. The packet filter has
// already applied the inbound policy, so a disallowed peer never connects.
func (d *Daemon) ListenMesh(ctx context.Context, network string, port int) (net.Listener, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("unsupported mesh network %q (only tcp)", network)
	}
	ln, err := d.dev.Net.Listen(port)
	if err != nil {
		return nil, err
	}
	slog.Info("Bound zero-trust mesh listener", "port", port)
	return ln, nil
}

// DialMesh connects to a peer's overlay address, first looking for a direct
// path to a peer that is not yet known. The destination enforces its own
// inbound policy.
func (d *Daemon) DialMesh(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid mesh address: %w", err)
	}
	if host != d.overlayIPv4 && !d.knowsOverlayIP(host) {
		_, _ = d.DiscoverAndConnectPeer(ctx, host)
	}
	return d.dev.Net.DialContext(ctx, network, address)
}

func (d *Daemon) knowsOverlayIP(ip string) bool {
	d.peersMu.RLock()
	defer d.peersMu.RUnlock()
	for _, p := range d.peers {
		if p.OverlayIPv4 == ip || p.OverlayIPv6 == ip {
			return true
		}
	}
	return false
}

// serveTunnel exposes a local service on the overlay: every accepted overlay
// connection is piped to localAddress. The listener closes when ctx ends.
func (d *Daemon) serveTunnel(ctx context.Context, ln net.Listener, localAddress string) {
	defer d.wg.Done()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var conns sync.WaitGroup
	defer conns.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conns.Add(1)
		go func() {
			defer conns.Done()
			dialCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			if err := d.tunnelClient.PipeTCP(dialCtx, conn, localAddress); err != nil {
				slog.Debug("Tunnel connection ended", "local", localAddress, "error", err)
			}
		}()
	}
}

// ExposeTunnel opens the overlay listener for a tunnel's port. The operator
// configured the tunnel explicitly, so its port is allowed through the inbound
// policy.
func (d *Daemon) ExposeTunnel(ctx context.Context, localAddress string) error {
	_, portStr, err := net.SplitHostPort(localAddress)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}
	d.AllowPort(fmt.Sprintf("%d/tcp", port))

	ln, err := d.ListenMesh(ctx, "tcp", port)
	if err != nil {
		// A service bound to 0.0.0.0 already answers on the overlay address.
		slog.Info("Tunnel port is already served on the overlay address", "port", port, "reason", err)
		return nil
	}
	d.wg.Add(1)
	go d.serveTunnel(ctx, ln, localAddress)
	return nil
}

// AssignOverlay gives the node its overlay addresses, outside of enrollment
// (static setups and tests).
func (d *Daemon) AssignOverlay(v4, v6 string) error {
	d.overlayIPv4, d.overlayIPv6 = v4, v6
	return d.dev.Configure(v4, v6)
}

// UDPPort is the local port of the shared WireGuard/STUN socket.
func (d *Daemon) UDPPort() int { return d.udpConn.LocalAddr().(*net.UDPAddr).Port }

// AddDirectPeer installs a WireGuard peer reachable at endpoint and records it
// as known, so DialMesh does not ask the plane about it. Exactly one side of a
// link should initiate: it keeps the path alive with a keepalive (which also
// starts the handshake), while the other only answers.
func (d *Daemon) AddDirectPeer(peer core.Node, endpoint string, initiate bool) error {
	var keepalive time.Duration
	if initiate {
		keepalive = 5 * time.Second
	}
	d.peersMu.Lock()
	d.peers[peer.PublicKey] = peer
	d.peersMu.Unlock()
	err := d.wgManager.ApplyPeer(wireguard.PeerConfig{
		PublicKey:           peer.PublicKey,
		Endpoint:            endpoint,
		AllowedIPs:          []string{peer.OverlayIPv4 + "/32"},
		PersistentKeepalive: keepalive,
	})
	if err == nil && initiate {
		agent.NudgeUntilHandshake(d.wgManager, peer.PublicKey, func() bool { return true })
	}
	return err
}

// PeerHandshaken reports whether a WireGuard session with the peer is up.
func (d *Daemon) PeerHandshaken(publicKey string) bool {
	at, err := d.wgManager.LastHandshake(publicKey)
	return err == nil && !at.IsZero()
}

// NodeID is the identity the plane assigned at enrollment.
func (d *Daemon) NodeID() uuid.UUID { return d.nodeID }
