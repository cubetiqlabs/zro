package node

import (
	"testing"
	"time"
)

func TestDirectAlive(t *testing.T) {
	t0 := time.Unix(1_000_000, 0)
	cases := []struct {
		name        string
		now, hs, rx time.Time
		wantAlive   bool
	}{
		{"fresh install, no handshake yet", t0.Add(2 * time.Second), time.Time{}, t0, true},
		{"never handshook past grace", t0.Add(directHandshakeGrace + time.Second), time.Time{}, t0, false},
		{"handshake from a previous session", t0.Add(directHandshakeGrace + time.Second), t0.Add(-time.Minute), t0, false},
		{"live session", t0.Add(10 * time.Minute), t0.Add(9 * time.Minute), t0.Add(10*time.Minute - 20*time.Second), true},
		{"silent session with a recent handshake", t0.Add(10 * time.Minute), t0.Add(9 * time.Minute), t0.Add(9 * time.Minute), false},
	}
	for _, c := range cases {
		if got := directAlive(c.now, t0, c.hs, c.rx); got != c.wantAlive {
			t.Errorf("%s: alive=%v, want %v", c.name, got, c.wantAlive)
		}
	}

	if retryBackoff(1) != directRetryMin || retryBackoff(2) != 2*directRetryMin || retryBackoff(50) != directRetryMax {
		t.Fatalf("backoff: %v %v %v", retryBackoff(1), retryBackoff(2), retryBackoff(50))
	}

	var p directPaths
	p.up("k", "100.64.0.2", t0)
	if !p.isDirect("k") {
		t.Fatal("up should mark the path direct")
	}
	p.down("k", "100.64.0.2", t0)
	if p.isDirect("k") || p.paths["k"].retryAt != t0.Add(directRetryMin) {
		t.Fatalf("down: %+v", p.paths["k"])
	}
}
