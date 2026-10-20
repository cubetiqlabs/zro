package acl

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/cubis/zro/pkg/core"
)

// Evaluator checks whether traffic between source and destination is allowed.
type Evaluator struct {
	rules         []core.ACLRule
	defaultAction core.ACLAction
}

// NewEvaluator creates a new ACL evaluator with sorted rules.
// If rules are provided, default action is to follow rule outcomes (defaulting to DENY if no rule matches).
// If no rules are provided, default action is ALLOW within the mesh.
func NewEvaluator(rules []core.ACLRule) *Evaluator {
	defaultAction := core.ACLActionAllow
	if len(rules) > 0 {
		defaultAction = core.ACLActionDeny
	}
	return &Evaluator{rules: rules, defaultAction: defaultAction}
}

// NewEvaluatorWithDefault creates an evaluator with explicit default action.
func NewEvaluatorWithDefault(rules []core.ACLRule, defaultAction core.ACLAction) *Evaluator {
	return &Evaluator{rules: rules, defaultAction: defaultAction}
}

// CanAccess evaluates if a source node with srcTags can access a destination node with dstTags
// on a specific protocol and port.
func (e *Evaluator) CanAccess(srcTags, dstTags []string, protocol string, port int) bool {
	return e.CanAccessWithIP("", srcTags, "", dstTags, protocol, port)
}

// CanAccessWithIP evaluates traffic including IP and tag matching.
func (e *Evaluator) CanAccessWithIP(srcIP string, srcTags []string, dstIP string, dstTags []string, protocol string, port int) bool {
	// If no rules exist, return configured default action
	if len(e.rules) == 0 {
		return e.defaultAction == core.ACLActionAllow
	}

	for _, rule := range e.rules {
		if !matchIP(rule.SourceIP, srcIP) {
			continue
		}
		if !matchIP(rule.DestIP, dstIP) {
			continue
		}
		if !matchTag(rule.SourceTag, srcTags) {
			continue
		}
		if !matchTag(rule.DestTag, dstTags) {
			continue
		}
		if !matchProtocol(rule.Protocol, protocol) {
			continue
		}
		if !matchPort(rule.Ports, port) {
			continue
		}

		return rule.Action == core.ACLActionAllow
	}

	// Default policy if no rule matched
	return e.defaultAction == core.ACLActionAllow
}

// EvaluateInbound evaluates incoming traffic at the client/peer node level.
// Supports Zero-Trust "default deny all" where only explicitly opened ports or authorized peers can connect.
func (e *Evaluator) EvaluateInbound(srcIP string, srcTags []string, protocol string, port int, allowedPorts []string, defaultDeny bool) bool {
	// 1. If node explicitly allows this port & protocol in its local policy (e.g. "5432/tcp" or "5432")
	if isPortAllowed(allowedPorts, protocol, port) {
		return true
	}

	// 2. If node has network-wide rules that match
	if len(e.rules) > 0 {
		return e.CanAccessWithIP(srcIP, srcTags, "", nil, protocol, port)
	}

	// 3. Fallback to default policy
	if defaultDeny {
		return false // Zero-trust default deny all
	}

	return true
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

		if matchProtocol(protoPart, protocol) && matchPort(portPart, port) {
			return true
		}
	}
	return false
}

func matchIP(pattern, ip string) bool {
	if pattern == "*" || pattern == "" || ip == "" {
		return true
	}
	// Exact match
	if pattern == ip {
		return true
	}
	// CIDR match (e.g. 100.64.0.0/10)
	if strings.Contains(pattern, "/") {
		_, ipNet, err := net.ParseCIDR(pattern)
		if err == nil {
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil && ipNet.Contains(parsedIP) {
				return true
			}
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

func matchPort(portPattern string, port int) bool {
	if portPattern == "*" || portPattern == "" || port == 0 {
		return true
	}

	// Format: "80,443" or "8000-8080" or single "5432"
	parts := strings.Split(portPattern, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			var start, end int
			if _, err := fmt.Sscanf(part, "%d-%d", &start, &end); err == nil {
				if port >= start && port <= end {
					return true
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err == nil && p == port {
				return true
			}
		}
	}

	return false
}
