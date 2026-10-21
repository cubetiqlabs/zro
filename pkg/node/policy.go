package node

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	v1 "github.com/cubis/zro/api/proto/v1"
	"github.com/cubis/zro/pkg/control/acl"
	"github.com/cubis/zro/pkg/core"
	"github.com/google/uuid"
)

// networkPolicy is the network-wide access policy distributed by the plane.
type networkPolicy struct {
	mu   sync.RWMutex
	eval *acl.Evaluator // nil until a policy with rules is installed
}

// setRules installs the rules; none means the network defines no central policy.
func (p *networkPolicy) setRules(rules []core.ACLRule) {
	var eval *acl.Evaluator
	if len(rules) > 0 {
		eval = acl.NewEvaluator(rules)
	}
	p.mu.Lock()
	p.eval = eval
	p.mu.Unlock()
}

// decide returns the verdict of the first matching network rule.
func (p *networkPolicy) decide(srcIP string, srcTags []string, dstIP string, dstTags []string, protocol string, port int) (allow, matched bool) {
	p.mu.RLock()
	eval := p.eval
	p.mu.RUnlock()
	if eval == nil {
		return false, false
	}
	return eval.Decide(srcIP, srcTags, dstIP, dstTags, protocol, port)
}

// centralDecision applies the network's rules to inbound traffic from srcIP.
// Source tags come from the peer list; destination tags are this node's own.
func (d *Daemon) centralDecision(srcIP, protocol string, port int) (allow, matched bool) {
	var srcTags []string
	d.peersMu.RLock()
	for _, p := range d.peers {
		if p.OverlayIPv4 == srcIP || p.OverlayIPv6 == srcIP {
			srcTags = []string(p.Tags)
			break
		}
	}
	d.peersMu.RUnlock()
	return d.policy.decide(srcIP, srcTags, d.overlayIPv4, d.cfg.Tags, protocol, port)
}

// fetchPolicy retrieves the network's access rules.
func (d *Daemon) fetchPolicy(ctx context.Context) ([]core.ACLRule, error) {
	if d.grpcClient != nil {
		g, err := d.grpcClient.GetACLPolicy(ctx)
		if err != nil {
			return nil, err
		}
		return rulesFromProto(g.Rules), nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.cfg.PlaneEndpoint+"/api/v1/acl/policy", nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("policy fetch rejected: status %d", resp.StatusCode)
	}
	var rules []core.ACLRule
	return rules, json.NewDecoder(resp.Body).Decode(&rules)
}

// syncPolicy refreshes the network access rules from the plane. On failure the
// previous rules stay in force: a flaky control plane must neither open nor
// close the node.
func (d *Daemon) syncPolicy(ctx context.Context) {
	rules, err := d.fetchPolicy(ctx)
	if err != nil {
		slog.Warn("Could not refresh the network access policy; keeping the current one", "error", err)
		return
	}
	d.policy.setRules(rules)
	slog.Info("Network access policy updated", "rules", len(rules))
}

func rulesFromProto(in []*v1.ACLRule) []core.ACLRule {
	rules := make([]core.ACLRule, 0, len(in))
	for _, r := range in {
		id, _ := uuid.Parse(r.Id)
		rules = append(rules, core.ACLRule{
			ID: id, Priority: int(r.Priority), SourceIP: r.SourceIp, DestIP: r.DestIp,
			SourceTag: r.SourceTag, DestTag: r.DestTag, Protocol: r.Protocol, Ports: r.Ports, Action: core.ACLAction(r.Action),
		})
	}
	return rules
}
