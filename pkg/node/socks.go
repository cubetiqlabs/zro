package node

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/cubetiqlabs/zro/pkg/tunnel"
)

// startSOCKS runs the optional SOCKS5 proxy. It only accepts loopback clients
// and only reaches overlay addresses, so it cannot become an open proxy into
// the host's own network.
func (d *Daemon) startSOCKS() error {
	addr := d.cfg.SOCKSListen
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("socks_listen %q: %w", addr, err)
	}
	if ip, err := netip.ParseAddr(host); err != nil || !ip.IsLoopback() {
		return fmt.Errorf("socks_listen must be a loopback address (got %q): the proxy has no authentication", host)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := tunnel.NewSOCKS5Server(d.dialOverlayOnly)
	d.socks = srv
	slog.Info("SOCKS5 proxy into the overlay listening", "addr", ln.Addr())
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		_ = srv.Serve(ln)
	}()
	return nil
}

// dialOverlayOnly dials through the mesh, refusing anything outside the
// overlay prefixes.
func (d *Daemon) dialOverlayOnly(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, errors.New("only overlay IP addresses can be reached (no name resolution)")
	}
	for _, p := range d.overlayPrefixes {
		if prefix, err := netip.ParsePrefix(p); err == nil && prefix.Contains(ip.Unmap()) {
			return d.DialMesh(ctx, network, address)
		}
	}
	return nil, fmt.Errorf("%s is outside the overlay", ip)
}
