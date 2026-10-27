package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	"github.com/cubetiqlabs/zro/pkg/control/acl"
)

// The node's own allow list has two sources: the config file (`allow:` and the
// older `allowed_inbound_ports:`), and what an operator opens at runtime with
// `zro allow`. The runtime part is kept in <state_dir>/policy.json so it
// survives restarts; the config part is only changed by editing the config.

// LocalPolicy is the node's own inbound policy as `zro policy` shows it.
type LocalPolicy struct {
	Allow        []string `json:"allow"`   // effective "ports/proto" entries
	Runtime      []string `json:"runtime"` // opened with `zro allow`, as typed
	DefaultDeny  bool     `json:"default_deny"`
	AllowPing    bool     `json:"allow_ping"`
	NetworkRules int      `json:"network_rules"`
}

type policyFile struct {
	Allow []string `json:"allow"`
}

func (d *Daemon) policyPath() string {
	if d.cfg.StateDir == "" {
		return ""
	}
	return filepath.Join(d.cfg.StateDir, "policy.json")
}

// loadLocalPolicy builds the allow list from the config and policy.json.
func (d *Daemon) loadLocalPolicy() error {
	configured, err := acl.NormalizeAllow(append(slices.Clone(d.cfg.Allow), d.cfg.AllowedInboundPorts...))
	if err != nil {
		return fmt.Errorf("node allow list: %w", err)
	}
	var f policyFile
	if path := d.policyPath(); path != "" {
		if raw, err := os.ReadFile(path); err == nil {
			if err := json.Unmarshal(raw, &f); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	runtime, err := acl.NormalizeAllow(f.Allow)
	if err != nil {
		return fmt.Errorf("%s: %w", d.policyPath(), err)
	}
	d.policyMu.Lock()
	d.configAllow, d.runtimeAllow = configured, f.Allow
	d.allowedPorts = append(configured, runtime...)
	d.policyMu.Unlock()
	return nil
}

// AllowService opens a service or port ("ssh", "5432/tcp") and persists it.
func (d *Daemon) AllowService(s string) error {
	entry, err := acl.NormalizeAllow([]string{s})
	if err != nil {
		return err
	}
	d.policyMu.Lock()
	defer d.policyMu.Unlock()
	if !slices.Contains(d.runtimeAllow, s) {
		d.runtimeAllow = append(d.runtimeAllow, s)
	}
	if !slices.Contains(d.allowedPorts, entry[0]) {
		d.allowedPorts = append(d.allowedPorts, entry[0])
	}
	slog.Info("Inbound allowed", "service", s, "entry", entry[0])
	return d.savePolicyLocked()
}

// DenyService closes what AllowService opened. Entries from the config file
// stay: the config is the source of truth for them.
func (d *Daemon) DenyService(s string) error {
	entry, err := acl.NormalizeAllow([]string{s})
	if err != nil {
		return err
	}
	d.policyMu.Lock()
	defer d.policyMu.Unlock()
	if slices.Contains(d.configAllow, entry[0]) {
		return fmt.Errorf("%s is allowed in the config file; remove it there", s)
	}
	d.runtimeAllow = slices.DeleteFunc(d.runtimeAllow, func(r string) bool {
		e, err := acl.NormalizeAllow([]string{r})
		return err == nil && e[0] == entry[0]
	})
	d.allowedPorts = slices.DeleteFunc(d.allowedPorts, func(p string) bool { return p == entry[0] })
	slog.Info("Inbound closed", "service", s, "entry", entry[0])
	return d.savePolicyLocked()
}

func (d *Daemon) savePolicyLocked() error {
	path := d.policyPath()
	if path == "" {
		return nil // ephemeral node: the change lasts until it stops
	}
	raw, _ := json.MarshalIndent(policyFile{Allow: d.runtimeAllow}, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (d *Daemon) localPolicy() LocalPolicy {
	d.policyMu.RLock()
	defer d.policyMu.RUnlock()
	d.policy.mu.RLock()
	rules := 0
	if d.policy.eval != nil {
		rules = d.policy.eval.Len()
	}
	d.policy.mu.RUnlock()
	return LocalPolicy{
		Allow: slices.Clone(d.allowedPorts), Runtime: slices.Clone(d.runtimeAllow),
		DefaultDeny: d.defaultDeny, AllowPing: d.allowPing, NetworkRules: rules,
	}
}
