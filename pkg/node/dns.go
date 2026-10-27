package node

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"

	"github.com/cubetiqlabs/zro/pkg/dataplane/netcfg"
	"golang.org/x/net/dns/dnsmessage"
)

// MagicDNS: each kernel-mode node answers <host>.<dns_domain> for the peers
// of its network on its own overlay address, and points the OS at itself for
// that domain only (split DNS). Names outside the domain are refused, so it is
// never an open resolver; peers cannot reach it anyway unless policy opens 53.

const dnsTTL = 60

// dnsLabel turns a hostname into the DNS label it answers to.
func dnsLabel(hostname string) string {
	b := []byte(strings.ToLower(hostname))
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			b[i] = '-'
		}
	}
	return strings.Trim(string(b), "-")
}

// lookupHost returns the overlay addresses of the node whose label is label,
// this node included.
func (d *Daemon) lookupHost(label string) (v4, v6 string, ok bool) {
	if dnsLabel(d.cfg.Hostname) == label {
		return d.overlayIPv4, d.overlayIPv6, true
	}
	d.peersMu.RLock()
	defer d.peersMu.RUnlock()
	for _, p := range d.peers {
		if dnsLabel(p.Hostname) == label {
			return p.OverlayIPv4, p.OverlayIPv6, true
		}
	}
	return "", "", false
}

// answerDNS builds the reply to one query; nil drops it.
func (d *Daemon) answerDNS(query []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil || h.Response {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	rh := dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionDesired: h.RecursionDesired}

	name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
	label, ok := strings.CutSuffix(name, "."+d.dnsDomain)
	var v4, v6 string
	switch {
	case d.dnsDomain == "" || !ok || strings.Contains(label, "."):
		rh.RCode = dnsmessage.RCodeRefused
	default:
		if v4, v6, ok = d.lookupHost(label); !ok {
			rh.RCode = dnsmessage.RCodeNameError
		}
	}

	b := dnsmessage.NewBuilder(make([]byte, 0, 512), rh)
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(q)
	_ = b.StartAnswers()
	rr := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: dnsTTL}
	if a, err := netip.ParseAddr(v4); err == nil && q.Type == dnsmessage.TypeA {
		_ = b.AResource(rr, dnsmessage.AResource{A: a.As4()})
	}
	if a, err := netip.ParseAddr(v6); err == nil && q.Type == dnsmessage.TypeAAAA {
		_ = b.AAAAResource(rr, dnsmessage.AAAAResource{AAAA: a.As16()})
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// startDNS serves MagicDNS on the overlay address (kernel mode only: a
// netstack node has no OS resolver to point at it).
func (d *Daemon) startDNS(ctx context.Context) {
	if !d.cfg.MagicDNS || d.dev.Userspace() || d.dnsDomain == "" || d.overlayIPv4 == "" {
		return
	}
	addr := net.JoinHostPort(d.overlayIPv4, "53")
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		slog.Warn("MagicDNS unavailable", "address", addr, "error", err)
		return
	}
	if err := netcfg.ConfigureDNS(d.cfg.InterfaceName, d.overlayIPv4, d.dnsDomain); err != nil {
		slog.Info("MagicDNS is up, but the OS resolver was not pointed at it; add it for the domain yourself",
			"nameserver", d.overlayIPv4, "domain", d.dnsDomain, "reason", err)
	} else {
		slog.Info("MagicDNS serving the mesh", "domain", d.dnsDomain, "nameserver", d.overlayIPv4)
	}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		go func() { <-ctx.Done(); _ = pc.Close() }()
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := d.answerDNS(buf[:n]); resp != nil {
				_, _ = pc.WriteTo(resp, from)
			}
		}
	}()
}
