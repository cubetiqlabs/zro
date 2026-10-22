package delegation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/google/uuid"
)

var (
	ErrNoHealthyPoP = errors.New("no healthy Edge PoP available for delegation")
)

// PoPScore holds calculated ranking metric for a PoP relative to a node.
type PoPScore struct {
	PoP   core.EdgePoP
	RTT   time.Duration
	Loss  float64
	Score float64 // lower score is better
}

// DelegationResult represents the Edge PoP assignment for a node.
type DelegationResult struct {
	PrimaryPoP   core.EdgePoP  `json:"primary_pop"`
	SecondaryPoP *core.EdgePoP `json:"secondary_pop,omitempty"`
	AssignedAt   time.Time     `json:"assigned_at"`
	Reason       string        `json:"reason"`
}

// Engine coordinates smart routing delegation based on latency probes and PoP health.
type Engine struct {
	mu           sync.RWMutex
	popRepo      core.EdgePoPRepository
	recentProbes map[uuid.UUID]map[string]core.LatencySample // nodeID -> popCode -> sample
}

// NewEngine creates a new smart routing delegation engine.
func NewEngine(popRepo core.EdgePoPRepository) *Engine {
	return &Engine{
		popRepo:      popRepo,
		recentProbes: make(map[uuid.UUID]map[string]core.LatencySample),
	}
}

// RecordProbe records a latency measurement from a node to an Edge PoP.
func (e *Engine) RecordProbe(sample core.LatencySample) {
	e.mu.Lock()
	defer e.mu.Unlock()

	nodeProbes, exists := e.recentProbes[sample.NodeID]
	if !exists {
		nodeProbes = make(map[string]core.LatencySample)
		e.recentProbes[sample.NodeID] = nodeProbes
	}
	nodeProbes[sample.PoPCode] = sample
}

// Forget drops a node's probe history (the node left or was reaped).
func (e *Engine) Forget(nodeID uuid.UUID) {
	e.mu.Lock()
	delete(e.recentProbes, nodeID)
	e.mu.Unlock()
}

// Prune drops samples older than maxAge, and nodes left without samples, so
// probe history stays bounded. Live nodes re-report every few seconds, which is
// why history is memory-only.
func (e *Engine) Prune(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, probes := range e.recentProbes {
		for code, sample := range probes {
			if sample.Timestamp.Before(cutoff) {
				delete(probes, code)
			}
		}
		if len(probes) == 0 {
			delete(e.recentProbes, id)
		}
	}
}

// Delegate selects the optimal primary and secondary Edge PoPs for a node.
func (e *Engine) Delegate(ctx context.Context, nodeID uuid.UUID) (*DelegationResult, error) {
	healthyPoPs, err := e.popRepo.ListHealthy(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list healthy Edge PoPs: %w", err)
	}
	if len(healthyPoPs) == 0 {
		return nil, ErrNoHealthyPoP
	}

	e.mu.RLock()
	nodeProbes := e.recentProbes[nodeID]
	e.mu.RUnlock()

	// Score each healthy PoP
	var scores []PoPScore
	for _, pop := range healthyPoPs {
		rtt := 500 * time.Millisecond // default penalty if unprobed
		loss := 0.0

		if probe, found := nodeProbes[pop.PoPCode]; found && time.Since(probe.Timestamp) < 10*time.Minute {
			rtt = probe.RTT
			loss = probe.PacketLoss
		}

		// Score algorithm: RTT in ms + (loss * 1000) - (weight factor)
		// Weight factor allows biasing higher-capacity PoPs
		rttMs := float64(rtt.Milliseconds())
		weightBonus := float64(pop.Weight) * 0.1
		score := rttMs + (loss * 1000) - weightBonus
		if score < 1 {
			score = 1
		}

		scores = append(scores, PoPScore{
			PoP:   pop,
			RTT:   rtt,
			Loss:  loss,
			Score: score,
		})
	}

	// Sort ascending by score (lowest score = fastest and lowest latency)
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].Score < scores[j].Score
	})

	result := &DelegationResult{
		PrimaryPoP: scores[0].PoP,
		AssignedAt: time.Now(),
		Reason:     fmt.Sprintf("Smart routed based on RTT %v (score: %.1f)", scores[0].RTT, scores[0].Score),
	}

	if len(scores) > 1 {
		sec := scores[1].PoP
		result.SecondaryPoP = &sec
	}

	return result, nil
}
