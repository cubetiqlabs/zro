package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	controlacl "github.com/cubetiqlabs/zro/pkg/control/acl"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/google/uuid"
)

// CreateACLRuleRequest is one network rule. Write it in shorthand,
//
//	{"name": "web to db", "from": "tag:web", "to": "db-1", "ports": "postgres"}
//
// or with the explicit source_*/dest_* fields; from/to win when both are set.
// from/to take "*", an IP, a CIDR, a tag (anything with a colon, such as
// "tag:web" or "role:db") or a node hostname. ports takes a service name
// (ssh, https, ping…) or "80,443/tcp".
type CreateACLRuleRequest struct {
	NetworkID   string         `json:"network_id,omitempty"`
	Name        string         `json:"name,omitempty"`
	Description string         `json:"description,omitempty"`
	Priority    int            `json:"priority,omitempty"`
	From        string         `json:"from,omitempty"`
	To          string         `json:"to,omitempty"`
	SourceIP    string         `json:"source_ip,omitempty"`
	DestIP      string         `json:"dest_ip,omitempty"`
	SourceTag   string         `json:"source_tag,omitempty"`
	DestTag     string         `json:"dest_tag,omitempty"`
	Protocol    string         `json:"protocol,omitempty"`
	Ports       string         `json:"ports,omitempty"`
	Action      core.ACLAction `json:"action,omitempty"`
}

// PolicyDocument is a network's whole rule set, as PUT and GET exchange it.
type PolicyDocument struct {
	Rules []CreateACLRuleRequest `json:"rules"`
}

// PolicyTestRequest asks whether from may reach to on port.
type PolicyTestRequest struct {
	From string `json:"from"`
	To   string `json:"to"`
	Port string `json:"port"` // "22/tcp", "ssh", "ping"
}

// PolicyTestResult is the network's verdict. Without a matching rule the
// destination node's own allow list and default_deny decide.
type PolicyTestResult struct {
	Verdict string        `json:"verdict"` // "allow", "deny" or "node-policy"
	Rule    *core.ACLRule `json:"rule,omitempty"`
}

var errUnknownHost = errors.New("unknown node hostname")

// hostResolver maps node hostnames in one network to their overlay IPv4,
// loading the node list once per request.
func (s *Server) hostResolver(ctx context.Context, networkID string) func(string) (*core.Node, error) {
	var nodes []core.Node
	loaded := false
	return func(host string) (*core.Node, error) {
		if !loaded {
			nodes, _ = s.db.Nodes.ListByNetworkID(ctx, networkID)
			loaded = true
		}
		for i := range nodes {
			if strings.EqualFold(nodes[i].Hostname, host) {
				return &nodes[i], nil
			}
		}
		return nil, fmt.Errorf("%w %q", errUnknownHost, host)
	}
}

// buildRule turns a request into a validated rule for networkID.
func buildRule(networkID string, req CreateACLRuleRequest, resolve func(string) (*core.Node, error)) (*core.ACLRule, error) {
	side := func(word string, ip, tag *string) error {
		if word == "" {
			return nil
		}
		ep := controlacl.ParseEndpoint(word)
		if ep.Hostname != "" {
			n, err := resolve(ep.Hostname)
			if err != nil {
				return err
			}
			ep.IP = n.OverlayIPv4
		}
		*ip, *tag = ep.IP, ep.Tag
		return nil
	}
	if err := side(req.From, &req.SourceIP, &req.SourceTag); err != nil {
		return nil, err
	}
	if err := side(req.To, &req.DestIP, &req.DestTag); err != nil {
		return nil, err
	}

	ports, proto := "*", "*"
	if req.Ports != "" {
		var err error
		if ports, proto, err = controlacl.ParseService(req.Ports); err != nil {
			return nil, err
		}
	}
	req.Protocol = strings.ToLower(req.Protocol)
	switch {
	case req.Protocol == "" || req.Protocol == "*":
		req.Protocol = proto
	case proto != "*" && proto != req.Protocol:
		return nil, fmt.Errorf("ports %q is %s but protocol is %s", req.Ports, proto, req.Protocol)
	}

	rule := &core.ACLRule{
		ID: uuid.New(), NetworkID: networkID, Name: req.Name, Description: req.Description,
		Priority: req.Priority, SourceIP: orAny(req.SourceIP), DestIP: orAny(req.DestIP),
		SourceTag: orAny(req.SourceTag), DestTag: orAny(req.DestTag), Protocol: req.Protocol, Ports: ports,
		Action:    core.ACLAction(strings.ToUpper(string(req.Action))),
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if rule.Priority <= 0 {
		rule.Priority = 100
	}
	if rule.Action == "" {
		rule.Action = core.ACLActionAllow
	}
	if err := controlacl.ValidateRule(rule); err != nil {
		return nil, err
	}
	return rule, nil
}

// ruleSummary is a one-line description of a rule for the audit log.
func ruleSummary(r *core.ACLRule) string {
	return fmt.Sprintf("%s %s/%s -> %s/%s %s/%s p%d %q", r.Action, r.SourceIP, r.SourceTag, r.DestIP, r.DestTag, r.Ports, r.Protocol, r.Priority, r.Name)
}

func orAny(s string) string {
	if s == "" {
		return "*"
	}
	return s
}

// requestFromRule is the inverse of buildRule, for PATCH and GET policy.
func requestFromRule(r core.ACLRule) CreateACLRuleRequest {
	return CreateACLRuleRequest{
		Name: r.Name, Description: r.Description, Priority: r.Priority,
		SourceIP: r.SourceIP, DestIP: r.DestIP, SourceTag: r.SourceTag, DestTag: r.DestTag,
		Protocol: r.Protocol, Ports: r.Ports, Action: r.Action,
	}
}

// ownedNetwork loads a network the caller's tenant owns, writing 404/403 if not.
func (s *Server) ownedNetwork(w http.ResponseWriter, r *http.Request, id string) (*core.Network, bool) {
	network, err := s.db.Networks.GetByID(r.Context(), id)
	if err != nil || network == nil {
		apiError(w, "network not found", http.StatusNotFound)
		return nil, false
	}
	if _, ok := s.authorizeNetwork(r.Context(), id); !ok {
		apiError(w, "forbidden: network does not belong to tenant", http.StatusForbidden)
		return nil, false
	}
	return network, true
}

// policyChanged tells the network's nodes to refetch their rules.
func (s *Server) policyChanged(network *core.Network, ruleID string) {
	scope := networkScope(network)
	s.broadcastDelta(scope, map[string]any{"event": "acl_rules_updated", "network_id": network.ID, "rule_id": ruleID})
	s.broadcastDelta(scope, map[string]any{"event": "mesh_graph_updated", "network_id": network.ID})
}

func ruleError(w http.ResponseWriter, err error) {
	apiError(w, "invalid ACL rule: "+err.Error(), http.StatusBadRequest)
}

func (s *Server) handleCreateACLRule(w http.ResponseWriter, r *http.Request) {
	var req CreateACLRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.NetworkID == "" {
		apiError(w, "network_id is required", http.StatusBadRequest)
		return
	}
	network, ok := s.ownedNetwork(w, r, req.NetworkID)
	if !ok {
		return
	}
	rule, err := buildRule(network.ID, req, s.hostResolver(r.Context(), network.ID))
	if err != nil {
		ruleError(w, err)
		return
	}
	if err := s.db.ACLs.Create(r.Context(), rule); err != nil {
		apiError(w, fmt.Sprintf("failed to create ACL rule: %v", err), http.StatusInternalServerError)
		return
	}
	slog.Info("Created ACL rule", "id", rule.ID, "network_id", rule.NetworkID, "action", rule.Action, "ports", rule.Ports)
	s.policyChanged(network, rule.ID.String())
	s.auditNetwork(r, network, "acl.create", rule.ID.String(), ruleSummary(rule))
	writeJSON(w, http.StatusCreated, rule)
}

// ruleForRequest loads the rule in the path, hiding other tenants' rules as missing.
func (s *Server) ruleForRequest(w http.ResponseWriter, r *http.Request) (*core.ACLRule, *core.Network, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		apiError(w, "invalid rule id", http.StatusBadRequest)
		return nil, nil, false
	}
	rule, err := s.db.ACLs.GetByID(r.Context(), id)
	if err != nil || rule == nil {
		apiError(w, "rule not found", http.StatusNotFound)
		return nil, nil, false
	}
	network, ok := s.authorizeNetwork(r.Context(), rule.NetworkID)
	if !ok {
		// Same response as a missing rule so rule IDs cannot be probed across tenants.
		apiError(w, "rule not found", http.StatusNotFound)
		return nil, nil, false
	}
	return rule, network, true
}

// handleUpdateACLRule changes the fields present in the body.
func (s *Server) handleUpdateACLRule(w http.ResponseWriter, r *http.Request) {
	rule, network, ok := s.ruleForRequest(w, r)
	if !ok {
		return
	}
	var patch CreateACLRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		apiError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req := requestFromRule(*rule)
	if patch.Ports != "" && patch.Protocol == "" {
		req.Protocol = "" // the new ports bring their own protocol
	}
	for _, f := range []struct{ dst, src *string }{
		{&req.Name, &patch.Name}, {&req.Description, &patch.Description},
		{&req.From, &patch.From}, {&req.To, &patch.To},
		{&req.SourceIP, &patch.SourceIP}, {&req.DestIP, &patch.DestIP},
		{&req.SourceTag, &patch.SourceTag}, {&req.DestTag, &patch.DestTag},
		{&req.Protocol, &patch.Protocol}, {&req.Ports, &patch.Ports},
	} {
		if *f.src != "" {
			*f.dst = *f.src
		}
	}
	if patch.Priority != 0 {
		req.Priority = patch.Priority
	}
	if patch.Action != "" {
		req.Action = patch.Action
	}
	updated, err := buildRule(network.ID, req, s.hostResolver(r.Context(), network.ID))
	if err != nil {
		ruleError(w, err)
		return
	}
	updated.ID, updated.CreatedAt = rule.ID, rule.CreatedAt
	if err := s.db.ACLs.Update(r.Context(), updated); err != nil {
		apiError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.policyChanged(network, updated.ID.String())
	s.auditNetwork(r, network, "acl.update", updated.ID.String(), ruleSummary(updated))
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleListACLRules(w http.ResponseWriter, r *http.Request) {
	netID := r.URL.Query().Get("network_id")
	if netID == "" {
		apiError(w, "network_id query parameter is required", http.StatusBadRequest)
		return
	}
	if _, ok := s.ownedNetwork(w, r, netID); !ok {
		return
	}
	rules, err := s.db.ACLs.ListByNetworkID(r.Context(), netID)
	if err != nil {
		apiError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writePage(w, r, rules)
}

func (s *Server) handleDeleteACLRule(w http.ResponseWriter, r *http.Request) {
	rule, network, ok := s.ruleForRequest(w, r)
	if !ok {
		return
	}
	if err := s.db.ACLs.Delete(r.Context(), rule.ID); err != nil {
		apiError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.policyChanged(network, rule.ID.String())
	s.auditNetwork(r, network, "acl.delete", rule.ID.String(), ruleSummary(rule))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleGetPolicy returns the network's rules in the form PUT accepts.
func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	network, ok := s.ownedNetwork(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	rules, err := s.db.ACLs.ListByNetworkID(r.Context(), network.ID)
	if err != nil {
		apiError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	doc := PolicyDocument{Rules: make([]CreateACLRuleRequest, 0, len(rules))}
	for _, rule := range rules {
		doc.Rules = append(doc.Rules, requestFromRule(rule))
	}
	writeJSON(w, http.StatusOK, doc)
}

// handlePutPolicy replaces the network's whole rule set in one transaction.
// Every rule is validated first, so a bad rule changes nothing.
func (s *Server) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	network, ok := s.ownedNetwork(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	var doc PolicyDocument
	if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
		apiError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	const maxRules = 1000
	if len(doc.Rules) > maxRules {
		apiError(w, fmt.Sprintf("a policy holds at most %d rules", maxRules), http.StatusBadRequest)
		return
	}
	resolve := s.hostResolver(r.Context(), network.ID)
	rules := make([]core.ACLRule, 0, len(doc.Rules))
	for i, req := range doc.Rules {
		rule, err := buildRule(network.ID, req, resolve)
		if err != nil {
			ruleError(w, fmt.Errorf("rule %d: %w", i+1, err))
			return
		}
		rules = append(rules, *rule)
	}
	if err := s.db.ACLs.Replace(r.Context(), network.ID, rules); err != nil {
		apiError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	slog.Info("Replaced network policy", "network_id", network.ID, "rules", len(rules))
	s.policyChanged(network, "")
	s.auditNetwork(r, network, "acl.replace", network.ID, fmt.Sprintf("%d rules", len(rules)))
	writeJSON(w, http.StatusOK, rules)
}

// handleTestPolicy evaluates the network rules for one flow.
func (s *Server) handleTestPolicy(w http.ResponseWriter, r *http.Request) {
	network, ok := s.ownedNetwork(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	var req PolicyTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.From == "" || req.To == "" {
		apiError(w, "from and to are required", http.StatusBadRequest)
		return
	}
	resolve := s.hostResolver(r.Context(), network.ID)
	side := func(word string) (ip string, tags []string, err error) {
		ep := controlacl.ParseEndpoint(word)
		switch {
		case ep.Hostname != "":
			n, err := resolve(ep.Hostname)
			if err != nil {
				return "", nil, err
			}
			return n.OverlayIPv4, n.Tags, nil
		case ep.Tag != "*":
			return "", []string{ep.Tag}, nil
		case ep.IP != "*":
			if n, err := s.db.Nodes.GetByOverlayIP(r.Context(), network.ID, ep.IP); err == nil && n != nil {
				return ep.IP, n.Tags, nil
			}
			return ep.IP, nil, nil
		}
		return "", nil, nil
	}
	srcIP, srcTags, err := side(req.From)
	if err != nil {
		apiError(w, err.Error(), http.StatusBadRequest)
		return
	}
	dstIP, dstTags, err := side(req.To)
	if err != nil {
		apiError(w, err.Error(), http.StatusBadRequest)
		return
	}
	ports, proto, err := controlacl.ParseService(orAny(req.Port))
	if err != nil {
		apiError(w, err.Error(), http.StatusBadRequest)
		return
	}
	port := 0
	if ports != "*" {
		_, _ = fmt.Sscanf(ports, "%d", &port)
	}

	rules, err := s.db.ACLs.ListByNetworkID(r.Context(), network.ID)
	if err != nil {
		apiError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	res := PolicyTestResult{Verdict: "node-policy"}
	if rule := controlacl.NewEvaluator(rules).Match(srcIP, srcTags, dstIP, dstTags, proto, port); rule != nil {
		res.Rule = rule
		res.Verdict = strings.ToLower(string(rule.Action))
	}
	writeJSON(w, http.StatusOK, res)
}
