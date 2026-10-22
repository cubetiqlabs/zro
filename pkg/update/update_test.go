package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		cur, latest string
		want        bool
	}{
		{"0.1.0", "v0.2.0", true},
		{"v0.2.0", "0.2.0", false},
		{"0.10.0", "0.9.0", false},
		{"0.2.0-rc.1", "0.2.0", true},
		{"0.2.0", "0.2.0-rc.1", false},
		{"dev", "9.9.9", false},
		{"0.1.0", "", false},
	} {
		if got := Newer(c.cur, c.latest); got != c.want {
			t.Errorf("Newer(%q,%q)=%v want %v", c.cur, c.latest, got, c.want)
		}
	}
}

// releaseServer serves a fake release whose archive holds bin, with the given checksum.
func releaseServer(t *testing.T, bin []byte, sum string) *httptest.Server {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "zro", Mode: 0o755, Size: int64(len(bin))})
	_, _ = tw.Write(bin)
	tw.Close()
	gz.Close()
	if sum == "" {
		s := sha256.Sum256(buf.Bytes())
		sum = hex.EncodeToString(s[:])
	}
	name := fmt.Sprintf("zro_1.2.3_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/repos/"+Repo+"/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name":"v1.2.3","assets":[{"name":%q,"browser_download_url":"%s/a"},{"name":"checksums.txt","browser_download_url":"%s/c"}]}`, name, srv.URL, srv.URL)
	})
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(buf.Bytes()) })
	mux.HandleFunc("/c", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "%s  %s\n", sum, name) })
	srv = httptest.NewServer(mux)
	APIBase = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

func TestApplyReplacesBinaryAndRejectsBadChecksum(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("archive format differs on windows")
	}
	exe := filepath.Join(t.TempDir(), "zro")
	_ = os.WriteFile(exe, []byte("old"), 0o755)

	releaseServer(t, []byte("new-binary"), strings.Repeat("0", 64))
	rel, err := Fetch(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), rel, exe); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("a bad checksum must be refused, got %v", err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatal("binary was modified despite checksum failure")
	}

	releaseServer(t, []byte("new-binary"), "")
	rel, _ = Fetch(context.Background(), "")
	if err := Apply(context.Background(), rel, exe); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "new-binary" {
		t.Fatalf("binary not replaced: %q", b)
	}
}

func TestNoticeChecksOncePerDay(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		fmt.Fprint(w, `{"tag_name":"v2.0.0"}`)
	}))
	defer srv.Close()
	APIBase = srv.URL
	dir, now := t.TempDir(), time.Now()

	if msg := Notice(context.Background(), dir, "1.0.0", now); !strings.Contains(msg, "v2.0.0") {
		t.Fatalf("expected a notice, got %q", msg)
	}
	if msg := Notice(context.Background(), dir, "1.0.0", now.Add(time.Hour)); msg == "" || hits != 1 {
		t.Fatalf("second call within a day must reuse the cache (hits=%d, msg=%q)", hits, msg)
	}
	if Notice(context.Background(), dir, "2.0.0", now.Add(25*time.Hour)) != "" || hits != 2 {
		t.Fatalf("after a day it re-checks, and an up-to-date build gets no notice (hits=%d)", hits)
	}
	if Notice(context.Background(), dir, "dev", now.Add(50*time.Hour)) != "" {
		t.Fatal("dev builds must never be nagged")
	}
}
