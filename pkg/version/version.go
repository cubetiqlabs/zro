// Package version reports the build the binary was made from. Release builds
// set Version, Commit and Date with -ldflags (see the Makefile); a plain
// `go build` falls back to the VCS data Go embeds.
package version

import (
	"runtime/debug"
	"strings"
)

// Set at link time: -X github.com/cubetiqlabs/zro/pkg/version.Version=v1.2.3
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// Info describes the running build.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Date    string `json:"date,omitempty"`
	Go      string `json:"go"`
}

// Get returns the build information, filling gaps from the embedded VCS data.
func Get() Info {
	info := Info{Version: Version, Commit: Commit, Date: Date}
	if bi, ok := debug.ReadBuildInfo(); ok {
		info.Go = bi.GoVersion
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = s.Value
				}
			case "vcs.time":
				if info.Date == "" {
					info.Date = s.Value
				}
			}
		}
	}
	if len(info.Commit) > 12 {
		info.Commit = info.Commit[:12]
	}
	return info
}

// String is the one-line form printed by `zro version`.
func (i Info) String() string {
	parts := []string{"zro " + i.Version}
	if i.Commit != "" {
		parts = append(parts, "commit "+i.Commit)
	}
	if i.Date != "" {
		parts = append(parts, "built "+i.Date)
	}
	parts = append(parts, i.Go)
	return strings.Join(parts, " · ")
}
