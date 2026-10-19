package acl

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cubis/zro/pkg/core"
)

// Evaluator checks whether traffic between source and destination is allowed.
type Evaluator struct {
	rules []core.ACLRule
}

// NewEvaluator creates a new ACL evaluator with sorted rules.
func NewEvaluator(rules []core.ACLRule) *Evaluator {
	return &Evaluator{rules: rules}
}

// CanAccess evaluates if a source node with srcTags can access a destination node with dstTags
// on a specific protocol and port.
func (e *Evaluator) CanAccess(srcTags, dstTags []string, protocol string, port int) bool {
	// If no rules exist, default to ALLOW within the same private network (or default deny if enterprise mode)
	if len(e.rules) == 0 {
		return true
	}

	for _, rule := range e.rules {
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
	if ruleProto == "*" || ruleProto == "" {
		return true
	}
	return strings.EqualFold(ruleProto, packetProto)
}

func matchPort(portPattern string, port int) bool {
	if portPattern == "*" || portPattern == "" {
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
