package acl

import (
	"fmt"
	"net/netip"
	"strings"
)

// services are the names accepted wherever a port is: "ssh" reads better in a
// policy than "22/tcp".
var services = map[string]struct{ ports, proto string }{
	"ssh":      {"22", "tcp"},
	"http":     {"80", "tcp"},
	"https":    {"443", "tcp"},
	"dns":      {"53", "*"},
	"ping":     {"*", "icmp"},
	"rdp":      {"3389", "tcp"},
	"postgres": {"5432", "tcp"},
	"mysql":    {"3306", "tcp"},
	"redis":    {"6379", "tcp"},
}

// ParseService reads a service name ("ssh"), a port spec with an optional
// protocol ("5432/tcp", "80,443/tcp", "8000-8100", "*/icmp") or "*".
func ParseService(s string) (ports, proto string, err error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if svc, ok := services[s]; ok {
		return svc.ports, svc.proto, nil
	}
	ports, proto, _ = strings.Cut(s, "/")
	if proto == "" {
		proto = "*"
	}
	if ports == "" {
		ports = "*"
	}
	switch proto {
	case "*", "tcp", "udp", "icmp":
	default:
		return "", "", fmt.Errorf("%q: protocol must be tcp, udp, icmp or *", s)
	}
	if err := validatePorts(ports); err != nil {
		return "", "", fmt.Errorf("%q: %w", s, err)
	}
	return ports, proto, nil
}

// NormalizeAllow expands a node's local allow list ("ssh", "5432/tcp") into
// the "ports/proto" entries PortAllowed reads.
func NormalizeAllow(entries []string) ([]string, error) {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		ports, proto, err := ParseService(e)
		if err != nil {
			return nil, err
		}
		out = append(out, ports+"/"+proto)
	}
	return out, nil
}

// Endpoint is one side of a rule written as a single word: "*", an IP, a
// CIDR, a tag (anything with a colon that is not an IP: "tag:web",
// "role:db"), or a node hostname.
type Endpoint struct {
	IP, Tag  string
	Hostname string // set when the word is a hostname; the caller resolves it to IP
}

// ParseEndpoint classifies a rule endpoint.
func ParseEndpoint(s string) Endpoint {
	s = strings.TrimSpace(s)
	switch {
	case s == "" || s == "*":
		return Endpoint{IP: "*", Tag: "*"}
	case isIPOrPrefix(s):
		return Endpoint{IP: s, Tag: "*"}
	case strings.Contains(s, ":"):
		return Endpoint{IP: "*", Tag: s}
	}
	return Endpoint{IP: "*", Tag: "*", Hostname: s}
}

func isIPOrPrefix(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}
