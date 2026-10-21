package node

import "testing"

func TestNextPath(t *testing.T) {
	cases := []struct {
		name    string
		cur     pathMode
		udpOK   bool
		fails   int
		relayUp bool
		want    pathMode
	}{
		{"healthy UDP stays", pathUDP, true, 0, true, pathUDP},
		{"one failure is tolerated", pathUDP, false, 1, true, pathUDP},
		{"repeated UDP failure with relay up switches", pathUDP, false, 2, true, pathRelay},
		{"repeated UDP failure without relay stays (failover handles it)", pathUDP, false, 5, false, pathUDP},
		{"relay stays while UDP is still blocked", pathRelay, false, 9, true, pathRelay},
		{"UDP recovery restores UDP", pathRelay, true, 0, true, pathUDP},
	}
	for _, c := range cases {
		if got := nextPath(c.cur, c.udpOK, c.fails, c.relayUp); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
