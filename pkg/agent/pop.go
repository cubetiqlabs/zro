// Package agent holds behaviour shared by the node and gateway daemons.
package agent

import (
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/cubetiqlabs/zro/pkg/dataplane/netcfg"
	"github.com/cubetiqlabs/zro/pkg/dataplane/wireguard"
)

const popKeepalive = 25 * time.Second

// PoPLink keeps an agent's tunnel to its current edge PoP. The PoP peer carries
// the whole overlay prefix (it relays to everything the agent has no direct
// path to); direct peers with longer prefixes win by WireGuard's longest-match.
type PoPLink struct {
	WG        *wireguard.Manager
	Interface string
	// OSRoutes sends the overlay prefixes into the interface. Disable it for
	// userspace (netstack) devices that have no host interface.
	OSRoutes bool

	mu      sync.Mutex
	current string // public key of the PoP currently linked
}

// Connect points the overlay prefixes at pop, removing the previous PoP peer so
// two PoPs never claim the same prefix.
func (l *PoPLink) Connect(pop core.EdgePoP, prefixes []string) error {
	if pop.PublicKey == "" {
		return errors.New("edge pop has no public key")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.current != "" && l.current != pop.PublicKey {
		if err := l.WG.RemovePeer(l.current); err != nil {
			slog.Debug("Could not remove previous PoP peer", "error", err)
		}
	}
	if l.OSRoutes {
		for _, cidr := range prefixes {
			if err := netcfg.AddSubnetRoute(l.Interface, cidr); err != nil {
				slog.Debug("Failed to add overlay route", "cidr", cidr, "error", err)
			}
		}
	}
	if err := l.WG.ApplyPeer(wireguard.PeerConfig{
		PublicKey:           pop.PublicKey,
		Endpoint:            pop.PublicEndpoint,
		AllowedIPs:          prefixes,
		PersistentKeepalive: popKeepalive,
	}); err != nil {
		return err
	}
	l.current = pop.PublicKey
	l.nudgeUntilHandshake(pop.PublicKey)
	return nil
}

// handshakeNudges are the delays after which a PoP peer without a handshake is
// poked. The PoP may not have learned about this node yet when the first
// initiation arrives (it syncs from the plane), and WireGuard would otherwise
// wait its full 5s retry before trying again.
var handshakeNudges = []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second}

func (l *PoPLink) nudgeUntilHandshake(popKey string) {
	NudgeUntilHandshake(l.WG, popKey, func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.current == popKey
	})
}

// NudgeUntilHandshake pokes a peer that has not completed a handshake, on a
// short schedule, until it does or wanted reports false. It never blocks.
func NudgeUntilHandshake(wg *wireguard.Manager, peerKey string, wanted func() bool) {
	go func() {
		for _, delay := range handshakeNudges {
			time.Sleep(delay)
			if !wanted() {
				return
			}
			if at, err := wg.LastHandshake(peerKey); err != nil || !at.IsZero() {
				return // established, or this device cannot report handshakes
			}
			_ = wg.Nudge(peerKey)
		}
	}()
}
