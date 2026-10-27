package acl

import "testing"

func TestParseServiceAndEndpoint(t *testing.T) {
	for in, want := range map[string]string{
		"ssh": "22/tcp", "SSH": "22/tcp", "ping": "*/icmp", "5432/tcp": "5432/tcp",
		"80,443/tcp": "80,443/tcp", "8000-8100": "8000-8100/*", "*": "*/*", "dns": "53/*",
	} {
		ports, proto, err := ParseService(in)
		if err != nil || ports+"/"+proto != want {
			t.Errorf("%q -> %s/%s, %v; want %s", in, ports, proto, err, want)
		}
	}
	for _, bad := range []string{"22/sctp", "70000", "ssh2", "1-"} {
		if _, _, err := ParseService(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}

	for in, want := range map[string]Endpoint{
		"*":             {IP: "*", Tag: "*"},
		"100.64.0.5":    {IP: "100.64.0.5", Tag: "*"},
		"100.64.0.0/24": {IP: "100.64.0.0/24", Tag: "*"},
		"fd00::1":       {IP: "fd00::1", Tag: "*"},
		"tag:web":       {IP: "*", Tag: "tag:web"},
		"role:db":       {IP: "*", Tag: "role:db"},
		"web-1":         {IP: "*", Tag: "*", Hostname: "web-1"},
	} {
		if got := ParseEndpoint(in); got != want {
			t.Errorf("%q -> %+v, want %+v", in, got, want)
		}
	}
	// A node's allow list is accepted by PortAllowed after normalization.
	allow, err := NormalizeAllow([]string{"ssh", "ping"})
	if err != nil || !PortAllowed(allow, "tcp", 22) || !PortAllowed(allow, "icmp", 0) || PortAllowed(allow, "tcp", 80) {
		t.Fatalf("normalized allow list %v, %v", allow, err)
	}
}
