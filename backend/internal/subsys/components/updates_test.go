package components

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

func TestLatestReleaseValidation(t *testing.T) {
	old := releaseAPIBase
	defer func() { releaseAPIBase = old }()
	rel := externalReleases["xray"]
	for _, tc := range []struct {
		name, tag, digest, url string
		pre                    bool
		status                 int
		ok                     bool
	}{
		{"stable", "v26.10.29", "sha256:" + strings.Repeat("a", 64), "", false, 200, true},
		{"no digest", "v26.10.29", "", "", false, 200, false},
		{"wrong asset", "v26.10.29", "sha256:" + strings.Repeat("a", 64), "https://evil.invalid/tool", false, 200, false},
		{"prerelease", "v26.10.29", "sha256:" + strings.Repeat("a", 64), "", true, 200, false},
		{"rate limit", "v26.10.29", "", "", false, 403, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url := rel.URL(tc.tag, runtime.GOARCH)
			assetURL := tc.url
			if assetURL == "" {
				assetURL = url
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/XTLS/Xray-core/releases/latest" {
					t.Errorf("path %s", r.URL.Path)
				}
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": tc.tag, "prerelease": tc.pre, "assets": []any{map[string]string{"name": filepath.Base(url), "browser_download_url": assetURL, "digest": tc.digest}}})
			}))
			defer server.Close()
			releaseAPIBase = server.URL + "/"
			got, err := latestRelease(context.Background(), rel)
			if (err == nil) != tc.ok {
				t.Fatalf("release %v error %v", got, err)
			}
			if tc.ok && (got.Version != tc.tag || len(got.SHA256[runtime.GOARCH]) != 64) {
				t.Fatal("unresolved asset")
			}
		})
	}
}

type updateTestRunner struct {
	calls     []string
	aptErr    error
	inventory string
}

func (r *updateTestRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	switch name {
	case "dpkg-query":
		if r.inventory != "" {
			return r.inventory, nil
		}
		return "unbound\tii \t1.0\nunbound-anchor\tii \t1.0\ndnsmasq\tii \t2.0\nabsent\trc \t1.0\n", nil
	case "apt-get":
		return "", r.aptErr
	case "apt-cache":
		return "unbound:\n  Installed: 1.0\n  Candidate: 1.1\nunbound-anchor:\n  Installed: 1.0\n  Candidate: 1.0\ndnsmasq:\n  Installed: 2.0\n  Candidate: 2.0\n", nil
	case "dpkg":
		return "", nil
	}
	return "", fmt.Errorf("unexpected command %s", name)
}
func (r *updateTestRunner) RunInput(ctx context.Context, _ string, n string, a ...string) (string, error) {
	return r.Run(ctx, n, a...)
}
func TestCheckUpdatesBatchesAndPreservesSourceErrors(t *testing.T) {
	for _, fail := range []bool{false, true} {
		r := &updateTestRunner{}
		if fail {
			r.aptErr = errors.New("offline")
		}
		s := New(r, testLogger{})
		rows, err := s.CheckUpdates(context.Background(), "unbound", "dnsmasq")
		if err != nil {
			t.Fatal(err)
		}
		if fail {
			if rows["unbound"].Error == "" {
				t.Fatal("source failure hidden")
			}
		} else {
			if !rows["unbound"].UpdateAvailable || rows["dnsmasq"].UpdateAvailable || rows["unbound"].Token == "" {
				t.Fatalf("%+v", rows)
			}
		}
		counts := map[string]int{}
		for _, c := range r.calls {
			counts[strings.Fields(c)[0]]++
		}
		if counts["dpkg-query"] != 1 || counts["apt-get"] != 1 || counts["apt-cache"] > 1 {
			t.Fatal(counts)
		}
	}
}
func TestReadinessDoesNotResolveOrDowngrade(t *testing.T) {
	rel := externalReleases["xray"]
	rel.Target = filepath.Join(t.TempDir(), "xray")
	if err := os.WriteFile(rel.Target, []byte("binary"), 0700); err != nil {
		t.Fatal(err)
	}
	s := New(outputVersionRunner{output: "Xray 26.7.28 (Xray)"}, testLogger{})
	old := releaseAPIBase
	releaseAPIBase = "http://127.0.0.1:1/"
	defer func() { releaseAPIBase = old }()
	if !s.externalCurrent(context.Background(), rel) {
		t.Fatal("working older version should remain ready offline")
	}
}
func TestProgressReportsBytesAndRetainsFailure(t *testing.T) {
	p := &Progress{}
	p.Start("update", "xray")
	p.Stage("xray", "download")
	ctx := context.WithValue(context.Background(), progressContextKey{}, p)
	_, err := io.Copy(io.Discard, downloadProgress(ctx, strings.NewReader("abc"), 3))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Snapshot(); !got.Active || got.Bytes != 3 || got.Total != 3 {
		t.Fatal(got)
	}
	p.Stage("xray", "restart")
	if p.Snapshot().Total != 0 {
		t.Fatal("stale percentage")
	}
	p.Finish(errors.New("failed"))
	if got := p.Snapshot(); got.Active || got.Error != "failed" {
		t.Fatal(got)
	}
	p.Start("check", "")
	if p.Snapshot().Error != "" {
		t.Fatal("previous error retained")
	}
}
func TestManagerSerializesAndCachesWithoutCommands(t *testing.T) {
	r := &updateTestRunner{}
	s := New(r, testLogger{})
	m := NewUpdateManager(s, filepath.Join(t.TempDir(), "updates.json"))
	started := make(chan struct{})
	release := make(chan struct{})
	var runs atomic.Int32
	m.Run = func(_ context.Context, fn func() error) error { runs.Add(1); close(started); <-release; return fn() }
	if err := m.Start(context.Background(), "", ""); err != nil {
		t.Fatal(err)
	}
	<-started
	if err := m.Start(context.Background(), "", ""); err == nil {
		t.Fatal("concurrent operation accepted")
	}
	for i := 0; i < 1000; i++ {
		_ = m.Snapshot()
	}
	if len(r.calls) != 0 {
		t.Fatal("snapshot ran commands")
	}
	close(release)
	deadline := time.Now().Add(3 * time.Second)
	for m.Snapshot().Operation.Active && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if m.Snapshot().Operation.Active || runs.Load() != 1 {
		t.Fatal("operation did not finish")
	}
	restored := NewUpdateManager(s, m.Path).Snapshot()
	if restored.CheckedAt.IsZero() || len(restored.Components) == 0 {
		t.Fatal("snapshot not persisted")
	}
}

func BenchmarkUpdateSnapshot(b *testing.B) {
	m := NewUpdateManager(New(&updateTestRunner{}, testLogger{}), filepath.Join(b.TempDir(), "none"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Snapshot()
	}
}

func TestRemovalInvalidatesPersistedUpdate(t *testing.T) {
	oldReleases := externalReleases
	defer func() { externalReleases = oldReleases }()
	target := filepath.Join(t.TempDir(), "xray")
	rel := externalReleases["xray"]
	rel.Target = target
	externalReleases = map[string]externalRelease{"xray": rel}
	if err := os.WriteFile(target, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(externalOwnerPath(rel), []byte(externalOwnerMark), 0600); err != nil {
		t.Fatal(err)
	}
	s := New(&updateTestRunner{}, testLogger{})
	m := NewUpdateManager(s, filepath.Join(t.TempDir(), "updates.json"))
	m.state.Components = map[string]ComponentUpdate{"xray": {Installed: "v1.0", UpdateAvailable: true}, "dnsproxy": {Installed: "v1.0"}}
	before := m.Snapshot()
	if err := s.removeProtected(context.Background(), config.ComponentInfo{ID: "xray", External: true}, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Snapshot().Components["xray"]; ok {
		t.Fatal("removed component still offered")
	}
	if !before.Components["xray"].UpdateAvailable {
		t.Fatal("published snapshot mutated")
	}
	saved := NewUpdateManager(s, m.Path).Snapshot()
	if len(saved.Components) != 1 || saved.Components["dnsproxy"].Installed == "" {
		t.Fatal("cache invalidation not persisted or unrelated row lost")
	}
}
func TestNextNightlyCheck(t *testing.T) {
	for _, tc := range []struct{ hour, want int }{{1, 2}, {3, 24}, {20, 7}} {
		now := time.Date(2026, 10, 30, tc.hour, 0, 0, 0, time.UTC)
		if got := untilNextCheck(now); got != time.Duration(tc.want)*time.Hour {
			t.Fatalf("hour %d: %v", tc.hour, got)
		}
	}
}

func TestSharedDependencyDoesNotOfferAbsentComponent(t *testing.T) {
	r := &updateTestRunner{inventory: "openssl\tii \t3.5.0\n"}
	rows, err := New(r, testLogger{}).CheckUpdates(context.Background(), "ocserv")
	if err != nil || len(rows) != 0 {
		t.Fatalf("absent ocserv offered because OpenSSL is installed: %v %v", rows, err)
	}
	for _, call := range r.calls {
		if strings.HasPrefix(call, "apt-") {
			t.Fatalf("unnecessary repository query: %s", call)
		}
	}
}

func TestSharedPackageInvalidatesAffectedCachedComponents(t *testing.T) {
	m := NewUpdateManager(New(&updateTestRunner{}, testLogger{}), filepath.Join(t.TempDir(), "updates.json"))
	m.state.Components = map[string]ComponentUpdate{"l2tp": {}, "pppoe": {}, "dnsproxy": {Installed: "v1.0"}}
	m.invalidate("l2tp")
	if rows := m.Snapshot().Components; len(rows) != 1 || rows["dnsproxy"].Installed == "" {
		t.Fatalf("shared PPP cache not invalidated: %v", rows)
	}
}
