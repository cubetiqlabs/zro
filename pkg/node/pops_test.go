package node

import (
	"testing"
	"time"
)

func TestPickPoP(t *testing.T) {
	ms := time.Millisecond
	alive := map[string]time.Duration{"KH": 20 * ms, "SG": 40 * ms}
	for _, c := range []struct {
		name       string
		cur, plane string
		alive      map[string]time.Duration
		fails      int
		want       string
	}{
		{"keep healthy home", "KH", "", alive, 0, "KH"},
		{"follow plane", "KH", "SG", alive, 0, "SG"},
		{"ignore unreachable plane pick", "KH", "US", alive, 0, "KH"},
		{"first PoP appears: fastest", "", "", alive, 0, "KH"},
		{"one failed probe: stay", "KH", "", map[string]time.Duration{"SG": 40 * ms}, 1, "KH"},
		{"two failed probes: fail over", "KH", "", map[string]time.Duration{"SG": 40 * ms}, 2, "SG"},
		{"nothing reachable: stay", "KH", "", nil, 5, "KH"},
		{"plane is down, cur dead, others alive", "KH", "KH", map[string]time.Duration{"SG": 40 * ms}, 2, "SG"},
	} {
		if got := pickPoP(c.cur, c.plane, c.alive, c.fails); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}
