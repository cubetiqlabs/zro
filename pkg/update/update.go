// Package update finds and installs new zro releases from GitHub Releases.
// Archives are named zro_<version>_<os>_<arch>.tar.gz (zip on Windows) and
// verified against the release's checksums.txt before anything is replaced.
package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Repo is the GitHub repository releases are read from.
const Repo = "cubetiqlabs/zro"

// APIBase is the GitHub API root (a variable so tests can point it elsewhere).
var APIBase = "https://api.github.com"

const (
	checkInterval = 24 * time.Hour
	maxArchive    = 200 << 20
)

// Release is the part of a GitHub release this package uses.
type Release struct {
	TagName    string `json:"tag_name"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// Version is the tag without its leading "v", the form baked into binaries.
func (r *Release) Version() string { return strings.TrimPrefix(r.TagName, "v") }

func get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = errors.New("response too large")
	}
	return b, err
}

// Fetch returns the latest stable release, or the one tagged tag when given.
func Fetch(ctx context.Context, tag string) (*Release, error) {
	path := "/releases/latest"
	if tag != "" {
		path = "/releases/tags/" + tag
	}
	b, err := get(ctx, APIBase+"/repos/"+Repo+path, 4<<20)
	if err != nil {
		return nil, err
	}
	var r Release
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// parse splits "v1.2.3-rc.1" into its numeric core and whether it is a prerelease.
func parse(v string) (core [3]int, pre bool, ok bool) {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "+"); i >= 0 {
		v = v[:i]
	}
	if i := strings.Index(v, "-"); i >= 0 {
		v, pre = v[:i], true
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return core, false, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return core, false, false
		}
		core[i] = n
	}
	return core, pre, true
}

// Newer reports whether latest is a later release than current. Development
// builds ("dev", commit hashes) are never considered out of date.
func Newer(current, latest string) bool {
	c, cPre, ok1 := parse(current)
	l, lPre, ok2 := parse(latest)
	if !ok1 || !ok2 {
		return false
	}
	for i := range c {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return cPre && !lPre
}

// Apply downloads rel's archive for this platform, verifies its checksum and
// replaces the executable at exe.
func Apply(ctx context.Context, rel *Release, exe string) error {
	ext := "tar.gz"
	if runtime.GOOS == "windows" {
		ext = "zip"
	}
	name := fmt.Sprintf("zro_%s_%s_%s.%s", rel.Version(), runtime.GOOS, runtime.GOARCH, ext)
	var archiveURL, sumsURL string
	for _, a := range rel.Assets {
		switch a.Name {
		case name:
			archiveURL = a.URL
		case "checksums.txt":
			sumsURL = a.URL
		}
	}
	if archiveURL == "" || sumsURL == "" {
		return fmt.Errorf("release %s has no %s (or checksums.txt) for %s/%s", rel.TagName, name, runtime.GOOS, runtime.GOARCH)
	}

	sums, err := get(ctx, sumsURL, 1<<20)
	if err != nil {
		return err
	}
	want := ""
	for _, line := range strings.Split(string(sums), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[1] == name {
			want = f[0]
		}
	}
	if want == "" {
		return fmt.Errorf("checksums.txt has no entry for %s", name)
	}
	archive, err := get(ctx, archiveURL, maxArchive)
	if err != nil {
		return err
	}
	if sum := sha256.Sum256(archive); hex.EncodeToString(sum[:]) != want {
		return fmt.Errorf("checksum mismatch for %s; refusing to install", name)
	}

	bin, err := extract(archive, ext)
	if err != nil {
		return err
	}
	return replace(exe, bin)
}

// extract returns the zro executable inside an archive.
func extract(archive []byte, ext string) ([]byte, error) {
	target := "zro"
	if runtime.GOOS == "windows" {
		target = "zro.exe"
	}
	if ext == "zip" {
		zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if filepath.Base(f.Name) == target {
				rc, err := f.Open()
				if err != nil {
					return nil, err
				}
				defer rc.Close()
				return io.ReadAll(io.LimitReader(rc, maxArchive))
			}
		}
		return nil, errors.New("archive has no zro executable")
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, errors.New("archive has no zro executable")
		}
		if err != nil {
			return nil, err
		}
		if filepath.Base(h.Name) == target {
			return io.ReadAll(io.LimitReader(tr, maxArchive))
		}
	}
}

// replace swaps exe for bin. A running executable can be renamed but not
// overwritten on Windows, so the old file is moved aside first everywhere.
func replace(exe string, bin []byte) error {
	next, old := exe+".new", exe+".old"
	if err := os.WriteFile(next, bin, 0o755); err != nil {
		return fmt.Errorf("cannot write next to %s (try running with elevated rights): %w", exe, err)
	}
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		_ = os.Remove(next)
		return err
	}
	if err := os.Rename(next, exe); err != nil {
		_ = os.Rename(old, exe) // restore
		_ = os.Remove(next)
		return err
	}
	_ = os.Remove(old) // fails on Windows while running; harmless, removed on the next update
	return nil
}

type checkState struct {
	CheckedAt time.Time `json:"checked_at"`
	Latest    string    `json:"latest"`
}

// Notice returns a one-line message when a newer release exists, or "". It asks
// GitHub at most once per day (and remembers the answer in stateDir), and never
// returns an error: a failed check must not get in the way of the command.
func Notice(ctx context.Context, stateDir, current string, now time.Time) string {
	if _, _, ok := parse(current); !ok || stateDir == "" {
		return ""
	}
	file := filepath.Join(stateDir, "update-check.json")
	var st checkState
	if b, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	if now.Sub(st.CheckedAt) >= checkInterval {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		st.CheckedAt = now
		if rel, err := Fetch(cctx, ""); err == nil {
			st.Latest = rel.TagName
		}
		if b, err := json.Marshal(st); err == nil {
			_ = os.MkdirAll(stateDir, 0o700)
			_ = os.WriteFile(file, b, 0o600)
		}
	}
	if Newer(current, st.Latest) {
		return fmt.Sprintf("A new version of zro is available: %s (you have %s). Run `zro update`.", st.Latest, current)
	}
	return ""
}
