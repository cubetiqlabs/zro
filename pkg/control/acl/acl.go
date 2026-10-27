package acl

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/cubetiqlabs/zro/pkg/core"
)

// Evaluator checks whether traffic between source and destination is allowed.
// Rules are compiled once, so Decide parses nothing and allocates nothing: it
// sits on the per-packet path of every node.
type Evaluator struct {
	rules         []compiledRule
	defaultAction core.ACLAction
}

type compiledRule struct {
	core.ACLRule
	src, dst addrMatch
	ports    []portRange // nil matches every port
}

// addrMatch is a compiled IP pattern: any, or a prefix (a single IP is a /32 or /128).
type addrMatch struct {
	any    bool
	prefix netip.Prefix
}

type portRange struct{ lo, hi int }

func compileAddr(pattern string) addrMatch {
	if pattern == "" || pattern == "*" {
		return addrMatch{any: true}
	}
	if p, err := netip.ParsePrefix(pattern); err == nil {
		return addrMatch{prefix: p.Masked()}
	}
	if a, err := netip.ParseAddr(pattern); err == nil {
		return addrMatch{prefix: netip.PrefixFrom(a, a.BitLen())}
	}
	return addrMatch{} // invalid: matches nothing (ValidateRule rejects these at write time)
}

func (m addrMatch) match(ip netip.Addr, ok bool) bool {
	if m.any {
		return true
	}
	return ok && m.prefix.IsValid() && m.prefix.Contains(ip.Unmap())
}

// compilePorts parses "80,443", "8000-8080" or "*". Unparseable parts are
// skipped, as before compilation.
func compilePorts(pattern string) []portRange {
	if pattern == "" || pattern == "*" {
		return nil
	}
	ranges := []portRange{}
	for _, part := range strings.Split(pattern, ",") {
		part = strings.TrimSpace(part)
		lo, hi := part, part
		if a, b, ok := strings.Cut(part, "-"); ok {
			lo, hi = a, b
		}
		l, err1 := strconv.Atoi(lo)
		h, err2 := strconv.Atoi(hi)
		if err1 == nil && err2 == nil {
			ranges = append(ranges, portRange{l, h})
		}
	}
	return ranges
}

func portsMatch(ranges []portRange, port int) bool {
	if ranges == nil || port == 0 {
		return true
	}
	for _, r := range ranges {
		if port >= r.lo && port <= r.hi {
			return true
		}
	}
	return false
}

// NewEvaluator creates a new ACL evaluator with sorted rules.
// If rules are provided, default action is to follow rule outcomes (defaulting to DENY if no rule matches).
// If no rules are provided, default action is ALLOW within the mesh.
func NewEvaluator(rules []core.ACLRule) *Evaluator {
	defaultAction := core.ACLActionAllow
	if len(rules) > 0 {
		defaultAction = core.ACLActionDeny
	}
	return NewEvaluatorWithDefault(rules, defaultAction)
}

// NewEvaluatorWithDefault creates an evaluator with explicit default action.
// Rules are evaluated by ascending Priority (a lower number wins); on a tie a
// DENY beats an ALLOW, so equal-priority rules can never open what another
// closes. The caller's slice is not modified.
func NewEvaluatorWithDefault(rules []core.ACLRule, defaultAction core.ACLAction) *Evaluator {
	sorted := append([]core.ACLRule(nil), rules...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority < sorted[j].Priority
		}
		return sorted[i].Action == core.ACLActionDeny && sorted[j].Action != core.ACLActionDeny
	})
	compiled := make([]compiledRule, len(sorted))
	for i, r := range sorted {
		compiled[i] = compiledRule{ACLRule: r, src: compileAddr(r.SourceIP), dst: compileAddr(r.DestIP), ports: compilePorts(r.Ports)}
	}
	return &Evaluator{rules: compiled, defaultAction: defaultAction}
}

// Len is the number of rules.
func (e *Evaluator) Len() int { return len(e.rules) }

// Decide reports the outcome of the first matching rule. matched is false when
// no rule applies, so the caller can fall back to its own policy.
func (e *Evaluator) Decide(srcIP string, srcTags []string, dstIP string, dstTags []string, protocol string, port int) (allow, matched bool) {
	src, srcErr := netip.ParseAddr(srcIP)
	dst, dstErr := netip.ParseAddr(dstIP)
	r := e.match(src, srcErr == nil, srcTags, dst, dstErr == nil, dstTags, protocol, port)
	if r == nil {
		return false, false
	}
	return r.Action == core.ACLActionAllow, true
}

// Match returns the first rule that applies, or nil.
func (e *Evaluator) Match(srcIP string, srcTags []string, dstIP string, dstTags []string, protocol string, port int) *core.ACLRule {
	src, srcErr := netip.ParseAddr(srcIP)
	dst, dstErr := netip.ParseAddr(dstIP)
	if r := e.match(src, srcErr == nil, srcTags, dst, dstErr == nil, dstTags, protocol, port); r != nil {
		return &r.ACLRule
	}
	return nil
}

func (e *Evaluator) match(src netip.Addr, srcOK bool, srcTags []string, dst netip.Addr, dstOK bool, dstTags []string, protocol string, port int) *compiledRule {
	for i := range e.rules {
		r := &e.rules[i]
		if r.src.match(src, srcOK) && r.dst.match(dst, dstOK) &&
			matchTag(r.SourceTag, srcTags) && matchTag(r.DestTag, dstTags) &&
			matchProtocol(r.Protocol, protocol) && portsMatch(r.ports, port) {
			return r
		}
	}
	return nil
}

// CanAccessWithIP evaluates traffic including IP and tag matching, falling
// back to the evaluator's default action.
func (e *Evaluator) CanAccessWithIP(srcIP string, srcTags []string, dstIP string, dstTags []string, protocol string, port int) bool {
	if allow, matched := e.Decide(srcIP, srcTags, dstIP, dstTags, protocol, port); matched {
		return allow
	}
	return e.defaultAction == core.ACLActionAllow
}

// PortAllowed reports whether a node's local allow list ("5432/tcp", "5432",
// "8000-8100/tcp", "*") admits protocol/port.
func PortAllowed(allowedPorts []string, protocol string, port int) bool {
	return isPortAllowed(allowedPorts, protocol, port)
}

func isPortAllowed(allowedPorts []string, protocol string, port int) bool {
	if len(allowedPorts) == 0 {
		return false
	}

	for _, ap := range allowedPorts {
		ap = strings.TrimSpace(ap)
		if ap == "*" {
			return true
		}

		// Handle format "5432/tcp" or "80/http"
		parts := strings.Split(ap, "/")
		portPart := parts[0]
		protoPart := "*"
		if len(parts) > 1 {
			protoPart = parts[1]
		}

		if matchProtocol(protoPart, protocol) && portsMatch(compilePorts(portPart), port) {
			return true
		}
	}
	return false
}

func matchTag(pattern string, tags []string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	for _, t := range tags {
		if t == pattern {
			return true
		}
	}
	return false
}

func matchProtocol(ruleProto, packetProto string) bool {
	if ruleProto == "*" || ruleProto == "" || packetProto == "*" || packetProto == "" {
		return true
	}
	return strings.EqualFold(ruleProto, packetProto)
}

// ValidateRule rejects rules the evaluator would silently misread (a typo in a
// CIDR or port list would otherwise turn into a rule that never matches, or one
// that matches too much).
func ValidateRule(r *core.ACLRule) error {
	if r.Action != core.ACLActionAllow && r.Action != core.ACLActionDeny {
		return fmt.Errorf("action must be ALLOW or DENY")
	}
	for _, ip := range []string{r.SourceIP, r.DestIP} {
		if err := validateIPPattern(ip); err != nil {
			return err
		}
	}
	switch strings.ToLower(r.Protocol) {
	case "", "*", "tcp", "udp", "icmp":
	default:
		return fmt.Errorf("protocol must be tcp, udp, icmp or *")
	}
	return validatePorts(r.Ports)
}

func validateIPPattern(p string) error {
	if p == "" || p == "*" {
		return nil
	}
	if strings.Contains(p, "/") {
		if _, _, err := net.ParseCIDR(p); err != nil {
			return fmt.Errorf("invalid CIDR %q", p)
		}
		return nil
	}
	if net.ParseIP(p) == nil {
		return fmt.Errorf("invalid IP %q", p)
	}
	return nil
}

func validatePorts(p string) error {
	if p == "" || p == "*" {
		return nil
	}
	for _, part := range strings.Split(p, ",") {
		part = strings.TrimSpace(part)
		lo, hi := part, part
		if a, b, ok := strings.Cut(part, "-"); ok {
			lo, hi = a, b
		}
		l, err1 := strconv.Atoi(lo)
		h, err2 := strconv.Atoi(hi)
		if err1 != nil || err2 != nil || l < 1 || h > 65535 || l > h {
			return fmt.Errorf("invalid port specification %q", part)
		}
	}
	return nil
}
