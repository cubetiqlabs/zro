package node

import (
	"context"
	"log/slog"
	"time"

	"github.com/cubetiqlabs/zro/pkg/core"
)

const (
	popRefreshInterval = 15 * time.Second
	popFailuresToMove  = 2 // consecutive failed probes of the current PoP before leaving it
)

// kickPoPs asks popWorker to refresh now (PoP health or homing changed).
func (d *Daemon) kickPoPs() {
	select {
	case d.popKick <- struct{}{}:
	default:
	}
}

func (d *Daemon) setCatalog(pops []core.EdgePoP) {
	d.popMu.Lock()
	d.pops = pops
	d.popMu.Unlock()
}

// pickPoP chooses the PoP to be homed at.
//   - The plane's choice wins when this node can reach it: the edges peer a
//     node at its home PoP only, so node and plane must agree.
//   - With no PoP yet, take the fastest reachable one.
//   - A PoP that failed popFailuresToMove probes in a row is replaced by the
//     fastest reachable one (the plane may be unreachable too).
//
// alive maps reachable PoP codes to their RTT.
func pickPoP(cur, plane string, alive map[string]time.Duration, fails int) string {
	if _, ok := alive[plane]; ok && plane != "" {
		return plane
	}
	_, curOK := alive[cur]
	if cur != "" && (curOK || fails < popFailuresToMove) {
		return cur
	}
	if next := fastest(alive, cur); next != "" {
		return next
	}
	return cur // nothing else reachable: stay put
}

// fastest returns the lowest-RTT code in alive other than skip ("" if none).
func fastest(alive map[string]time.Duration, skip string) string {
	best := ""
	for code, rtt := range alive {
		if code == skip {
			continue
		}
		if best == "" || rtt < alive[best] || (rtt == alive[best] && code < best) {
			best = code
		}
	}
	return best
}

// popWorker keeps the node attached to a good Edge PoP: it refetches the PoP
// catalog, probes every PoP, reports the results (so the plane can pick the
// nearest), follows the plane's choice of home PoP, and fails over locally when
// the current PoP stops answering. UDP-blocked paths fall back to the TCP relay.
func (d *Daemon) popWorker(ctx context.Context) {
	defer d.wg.Done()
	ticker := time.NewTicker(popRefreshInterval)
	defer ticker.Stop()

	var fails int
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-d.popKick:
		}
		fails = d.refreshPoPs(ctx, fails)
	}
}

// refreshPoPs runs one refresh round and returns the updated consecutive
// failure count of the current PoP.
func (d *Daemon) refreshPoPs(ctx context.Context, fails int) int {
	pops, err := d.fetchPoPs(ctx)
	if err != nil {
		slog.Debug("PoP catalog refresh failed; using the last known catalog", "error", err)
		d.popMu.RLock()
		pops = d.pops
		d.popMu.RUnlock()
	} else {
		d.setCatalog(pops)
	}
	if len(pops) == 0 {
		return fails
	}

	samples, _ := d.probePoPs(ctx, pops)
	alive := make(map[string]time.Duration, len(samples))
	plane := ""
	for _, smp := range samples {
		if smp.PacketLoss < 1 {
			alive[smp.PoPCode] = smp.RTT
		}
		smp.NodeID = d.nodeID
		if code := d.reportProbe(ctx, smp); code != "" {
			plane = code
		}
	}

	d.popMu.RLock()
	cur := d.primaryPoP
	d.popMu.RUnlock()

	_, curOK := alive[cur.PoPCode]
	if cur.PoPCode == "" || curOK {
		fails = 0
	} else {
		fails++
	}

	// UDP-blocked but the relay is up: the PoP is usable, do not move away from it.
	moveFails := fails
	if d.relay.isUp() {
		moveFails = 0
	}
	want := pickPoP(cur.PoPCode, plane, alive, moveFails)
	if want != "" && want != cur.PoPCode {
		if next, ok := findPoP(pops, want); ok {
			second := fastest(alive, want)
			slog.Info("Switching Edge PoP", "from", cur.PoPCode, "to", want, "plane_choice", plane)
			d.popMu.Lock()
			d.primaryPoP = next
			d.secondaryPoP = nil
			if sec, ok := findPoP(pops, second); ok {
				d.secondaryPoP = &sec
			}
			d.popMu.Unlock()
			if err := d.connectToEdgePoP(next); err != nil {
				slog.Warn("Failed to connect to Edge PoP", "pop", want, "error", err)
			}
			return 0
		}
	}

	// Same PoP: if its UDP path is dead but the TCP relay works, tunnel through it.
	if cur.PoPCode != "" {
		d.relay.mu.Lock()
		mode := d.relay.mode
		d.relay.mu.Unlock()
		if next := nextPath(mode, curOK, fails, d.relay.isUp()); next != mode {
			slog.Warn("Edge PoP path changed", "pop", cur.PoPCode, "relay", next == pathRelay)
			_ = d.applyPath(cur, next)
		}
	}
	return fails
}

func findPoP(pops []core.EdgePoP, code string) (core.EdgePoP, bool) {
	for _, p := range pops {
		if p.PoPCode == code {
			return p, true
		}
	}
	return core.EdgePoP{}, false
}
