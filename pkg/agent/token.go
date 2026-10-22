package agent

import (
	"log/slog"

	controlauth "github.com/cubetiqlabs/zro/pkg/control/auth"
	"github.com/cubetiqlabs/zro/pkg/identity"
)

// LoadToken restores the node token saved by a previous run, so the agent can
// prove it is the same node when it re-enrolls. A missing file is normal.
func LoadToken(stateDir, name string, holder *controlauth.TokenHolder) {
	if stateDir == "" {
		return
	}
	if tok, err := identity.ReadSecret(stateDir, name); err == nil {
		holder.Set(tok)
	}
}

// SaveToken persists the token issued at enrollment (mode 0600).
func SaveToken(stateDir, name, token string) {
	if stateDir == "" || token == "" {
		return
	}
	if err := identity.WriteSecret(stateDir, name, token); err != nil {
		slog.Error("Could not persist the node token; the next restart will need the node removed and re-enrolled", "error", err)
	}
}
