package version

import "testing"

func TestGetAndString(t *testing.T) {
	old := Version
	Version = "v9.9.9"
	defer func() { Version = old }()

	info := Get()
	if info.Version != "v9.9.9" || info.Go == "" {
		t.Fatalf("unexpected info %+v", info)
	}
	if got := (Info{Version: "v1", Commit: "abc", Go: "go1.27"}).String(); got != "zro v1 · commit abc · go1.27" {
		t.Fatalf("unexpected string %q", got)
	}
}
