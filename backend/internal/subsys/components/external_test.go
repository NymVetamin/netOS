package components

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type quietLogger struct{}

func (quietLogger) Infof(string, ...any) {}
func (quietLogger) Warnf(string, ...any) {}

// tarGz собирает архив того же вида, что и релиз dnsproxy: бинарник лежит
// внутри каталога с именем платформы.
func tarGz(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zipArchive(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func release(t *testing.T, want string) externalRelease {
	t.Helper()
	return externalRelease{
		Version:       "v1.0.0",
		URL:           func(string, string) string { return "https://example.invalid/a.tar.gz" },
		SHA256:        map[string]string{"amd64": want, "arm64": want},
		FileInArchive: "dnsproxy",
		Target:        filepath.Join(t.TempDir(), "dnsproxy"),
		VersionArgs:   []string{"--version"},
	}
}

type versionRunner struct {
	output string
	calls  int
}

func (r *versionRunner) Run(context.Context, string, ...string) (string, error) {
	r.calls++
	return r.output, nil
}

func (r *versionRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestInstalledExternalReleaseIsNotDownloadedAgain(t *testing.T) {
	target := filepath.Join(t.TempDir(), "xray")
	if err := os.WriteFile(target, []byte("installed"), 0o755); err != nil {
		t.Fatal(err)
	}
	rel := externalRelease{
		Version: "v26.7.28", Target: target, VersionArgs: []string{"version"},
		URL:    func(string, string) string { return "https://example.invalid/xray.zip" },
		SHA256: map[string]string{runtime.GOARCH: strings.Repeat("0", 64)},
	}
	if err := os.WriteFile(externalOwnerPath(rel), []byte(externalOwnerMark), 0o600); err != nil {
		t.Fatal(err)
	}
	originalRelease := externalReleases["xray"]
	externalReleases["xray"] = rel
	defer func() { externalReleases["xray"] = originalRelease }()
	originalFetch := fetch
	fetch = func(context.Context, string) ([]byte, error) {
		t.Fatal("актуальный Xray не должен скачиваться повторно")
		return nil, nil
	}
	defer func() { fetch = originalFetch }()

	runner := &versionRunner{output: "Xray 26.7.28 (Xray, Penetrates Everything.)"}
	s := New(runner, quietLogger{})
	if err := s.installExternal(context.Background(), config.ComponentInfo{ID: "xray", External: true}); err != nil {
		t.Fatal(err)
	}
	if runner.calls != 1 {
		t.Fatalf("версия проверена %d раз вместо одного", runner.calls)
	}
}

func TestForeignExternalTargetIsNeverAdoptedOverwrittenOrRemoved(t *testing.T) {
	target := filepath.Join(t.TempDir(), "xray")
	original := []byte("administrator binary")
	if err := os.WriteFile(target, original, 0o755); err != nil {
		t.Fatal(err)
	}
	rel := externalRelease{Version: "v26.7.28", Target: target, VersionArgs: []string{"version"}}
	originalRelease := externalReleases["xray"]
	externalReleases["xray"] = rel
	t.Cleanup(func() { externalReleases["xray"] = originalRelease })

	s := New(&versionRunner{output: "Xray 26.7.28"}, quietLogger{})
	info := config.ComponentInfo{ID: "xray", External: true}
	anyInstalled, allInstalled := s.componentState(context.Background(), info)
	if !anyInstalled || allInstalled {
		t.Fatalf("foreign state any=%v all=%v", anyInstalled, allInstalled)
	}
	if err := s.installExternal(context.Background(), info); err == nil || !strings.Contains(err.Error(), "не принадлежит netOS") {
		t.Fatalf("foreign collision accepted: %v", err)
	}
	if err := s.remove(context.Background(), info); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != string(original) {
		t.Fatalf("foreign target changed: %q, %v", got, err)
	}
	if _, err := os.Stat(externalOwnerPath(rel)); !os.IsNotExist(err) {
		t.Fatalf("foreign target was adopted: %v", err)
	}
}

func TestExternalOwnershipRejectsSymlinkAndLooseMarker(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "xray")
	if err := os.WriteFile(target, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	rel := externalRelease{Target: target}
	markerPayload := filepath.Join(dir, "payload")
	if err := os.WriteFile(markerPayload, []byte(externalOwnerMark), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(markerPayload, externalOwnerPath(rel)); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if externalOwned(rel) {
		t.Fatal("symlink ownership marker was accepted")
	}
	if err := os.Remove(externalOwnerPath(rel)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(externalOwnerPath(rel), []byte(externalOwnerMark), 0o644); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && externalOwned(rel) {
		t.Fatal("world-readable ownership marker was accepted")
	}
}

func TestApplyMigratesCurrentLegacyExternalExactlyOnce(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "xray")
	original := []byte("legacy netOS binary")
	if err := os.WriteFile(target, original, 0o755); err != nil {
		t.Fatal(err)
	}
	rel := externalRelease{Version: "v26.7.28", Target: target, VersionArgs: []string{"version"}}
	originalCatalog := config.Catalog
	originalRelease := externalReleases["xray"]
	config.Catalog = []config.ComponentInfo{{ID: "xray", Title: "Xray", External: true}}
	externalReleases["xray"] = rel
	t.Cleanup(func() {
		config.Catalog = originalCatalog
		externalReleases["xray"] = originalRelease
	})

	s := New(&versionRunner{output: "Xray 26.7.28"}, quietLogger{})
	s.ExternalMigrationPath = filepath.Join(dir, "external-ownership-v1")
	cfg := &config.Config{Components: []config.Component{{ID: "xray", Installed: true}}}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != string(original) {
		t.Fatalf("legacy target changed: %q, %v", got, err)
	}
	if got, err := os.ReadFile(externalOwnerPath(rel)); err != nil || string(got) != externalOwnerMark {
		t.Fatalf("ownership marker: %q, %v", got, err)
	}
	if got, err := os.ReadFile(s.ExternalMigrationPath); err != nil || string(got) != externalMigrationMark {
		t.Fatalf("migration sentinel: %q, %v", got, err)
	}
	if err := s.remove(context.Background(), config.Catalog[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("adopted legacy target remains: %v", err)
	}
}

func TestCompletedExternalMigrationNeverAdoptsCurrentForeignTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "xray")
	original := []byte("administrator binary")
	if err := os.WriteFile(target, original, 0o755); err != nil {
		t.Fatal(err)
	}
	rel := externalRelease{Version: "v26.7.28", Target: target, VersionArgs: []string{"version"}}
	originalCatalog := config.Catalog
	originalRelease := externalReleases["xray"]
	config.Catalog = []config.ComponentInfo{{ID: "xray", Title: "Xray", External: true}}
	externalReleases["xray"] = rel
	t.Cleanup(func() {
		config.Catalog = originalCatalog
		externalReleases["xray"] = originalRelease
	})

	s := New(&versionRunner{output: "Xray 26.7.28"}, quietLogger{})
	s.ExternalMigrationPath = filepath.Join(dir, "external-ownership-v1")
	if err := os.WriteFile(s.ExternalMigrationPath, []byte(externalMigrationMark), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Components: []config.Component{{ID: "xray", Installed: true}}}
	err := s.Apply(context.Background(), cfg)
	if err == nil {
		t.Fatalf("post-migration foreign target accepted: %v", err)
	}
	if _, err := os.Stat(externalOwnerPath(rel)); !os.IsNotExist(err) {
		t.Fatalf("foreign target was adopted: %v", err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != string(original) {
		t.Fatalf("foreign target changed: %q, %v", got, err)
	}
}

func TestExternalMigrationRollsBackMarkerWhenSentinelCannotBeWritten(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "xray")
	if err := os.WriteFile(target, []byte("legacy"), 0o755); err != nil {
		t.Fatal(err)
	}
	rel := externalRelease{Version: "v26.7.28", Target: target, VersionArgs: []string{"version"}}
	originalCatalog := config.Catalog
	originalRelease := externalReleases["xray"]
	config.Catalog = []config.ComponentInfo{{ID: "xray", Title: "Xray", External: true}}
	externalReleases["xray"] = rel
	t.Cleanup(func() {
		config.Catalog = originalCatalog
		externalReleases["xray"] = originalRelease
	})

	blocked := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(&versionRunner{output: "Xray 26.7.28"}, quietLogger{})
	s.ExternalMigrationPath = filepath.Join(blocked, "sentinel")
	cfg := &config.Config{Components: []config.Component{{ID: "xray", Installed: true}}}
	if err := s.Apply(context.Background(), cfg); err == nil {
		t.Fatal("unwritable sentinel was accepted")
	}
	if _, err := os.Stat(externalOwnerPath(rel)); !os.IsNotExist(err) {
		t.Fatalf("ownership marker survived failed transaction: %v", err)
	}
}

func TestExternalMigrationRejectsSymlinkSentinel(t *testing.T) {
	dir := t.TempDir()
	payload := filepath.Join(dir, "payload")
	if err := os.WriteFile(payload, []byte(externalMigrationMark), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(&versionRunner{}, quietLogger{})
	s.ExternalMigrationPath = filepath.Join(dir, "sentinel")
	if err := os.Symlink(payload, s.ExternalMigrationPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := s.Apply(context.Background(), &config.Config{}); err == nil || !strings.Contains(err.Error(), "не является обычным файлом") {
		t.Fatalf("symlink migration sentinel accepted: %v", err)
	}
}

func TestRemoveOwnedExternalPreservesUnmarkedTargets(t *testing.T) {
	dir := t.TempDir()
	owned := filepath.Join(dir, "owned")
	foreign := filepath.Join(dir, "foreign")
	for _, path := range []string{owned, foreign} {
		if err := os.WriteFile(path, []byte(filepath.Base(path)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(owned+".netos-owned", []byte(externalOwnerMark), 0o600); err != nil {
		t.Fatal(err)
	}
	original := externalReleases
	externalReleases = map[string]externalRelease{
		"owned": {Target: owned}, "foreign": {Target: foreign},
	}
	t.Cleanup(func() { externalReleases = original })
	if err := RemoveOwnedExternal(""); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{owned, owned + ".netos-owned"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("owned artifact remains: %s (%v)", path, err)
		}
	}
	if content, err := os.ReadFile(foreign); err != nil || string(content) != "foreign" {
		t.Fatalf("foreign target changed: %q, %v", content, err)
	}
}

// Установка чужого бинарника с правами root — это ровно то, от чего защищает
// сумма, поэтому подменённый архив обязан быть отвергнут.
func TestInstallRejectsTamperedArchive(t *testing.T) {
	good := tarGz(t, "linux-amd64/dnsproxy", []byte("настоящий бинарник"))
	evil := tarGz(t, "linux-amd64/dnsproxy", []byte("подменённый бинарник"))

	original := fetch
	fetch = func(context.Context, string) ([]byte, error) { return evil, nil }
	defer func() { fetch = original }()

	rel := release(t, sum(good))
	s := New(nil, quietLogger{})
	err := s.installRelease(context.Background(), "dnsproxy", rel)
	if err == nil || !strings.Contains(err.Error(), "сумма") {
		t.Fatalf("подменённый архив принят: %v", err)
	}
	if _, statErr := os.Stat(rel.Target); statErr == nil {
		t.Fatal("подменённый бинарник записан на диск")
	}
}

func TestInstallExtractsBinaryFromArchive(t *testing.T) {
	payload := []byte("настоящий бинарник")
	archive := tarGz(t, "linux-amd64/dnsproxy", payload)

	original := fetch
	fetch = func(context.Context, string) ([]byte, error) { return archive, nil }
	defer func() { fetch = original }()

	rel := release(t, sum(archive))
	s := New(nil, quietLogger{})
	if err := s.installRelease(context.Background(), "dnsproxy", rel); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(rel.Target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("распакован не тот файл: %q", got)
	}
	info, err := os.Stat(rel.Target)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("файл не исполняемый: %v", info.Mode())
	}
}

func TestInstallExtractsBinaryFromZIP(t *testing.T) {
	payload := []byte("xray-binary")
	archive := zipArchive(t, "nested/xray", payload)
	original := fetch
	fetch = func(context.Context, string) ([]byte, error) { return archive, nil }
	defer func() { fetch = original }()
	rel := release(t, sum(archive))
	rel.FileInArchive = "xray"
	rel.Target = filepath.Join(t.TempDir(), "xray")
	rel.ZIP = true
	s := New(nil, quietLogger{})
	if err := s.installRelease(context.Background(), "xray", rel); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(rel.Target)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("распакован не тот файл: %q (%v)", got, err)
	}
}

// Имя внутри архива приходит извне: «../» в нём не должно уводить запись мимо
// цели, поэтому берётся только базовое имя.
func TestExtractIgnoresPathsInArchive(t *testing.T) {
	archive := tarGz(t, "../../etc/passwd", []byte("не тот файл"))
	if _, err := extractFile(archive, "dnsproxy"); err == nil {
		t.Fatal("файл с чужим именем принят за нужный")
	}
}

func TestExternalPayloadLimitIsExplicitForRawZIPAndTar(t *testing.T) {
	originalLimit := maxExternalBytes
	maxExternalBytes = 4
	t.Cleanup(func() { maxExternalBytes = originalLimit })
	if got, err := readExternalData(bytes.NewReader([]byte("1234"))); err != nil || string(got) != "1234" {
		t.Fatalf("exact limit rejected: %q (%v)", got, err)
	}
	if _, err := readExternalData(bytes.NewReader([]byte("12345"))); err == nil {
		t.Fatal("oversized raw payload was silently truncated")
	}
	if _, err := extractZIPFile(zipArchive(t, "tool", []byte("12345")), "tool"); err == nil {
		t.Fatal("oversized ZIP payload was silently truncated")
	}
	if _, err := extractFile(tarGz(t, "tool", []byte("12345")), "tool"); err == nil {
		t.Fatal("oversized TAR payload was silently truncated")
	}
}

func TestFetchAcceptsSuccessAndRejectsHTTPAndURLFailures(t *testing.T) {
	realFetch := fetch
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/failure" {
			http.Error(w, "no", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("archive"))
	}))
	t.Cleanup(server.Close)
	got, err := realFetch(context.Background(), server.URL+"/ok")
	if err != nil || string(got) != "archive" {
		t.Fatalf("successful fetch=%q (%v)", got, err)
	}
	if _, err := realFetch(context.Background(), server.URL+"/failure"); err == nil {
		t.Fatal("HTTP failure was accepted")
	}
	if _, err := realFetch(context.Background(), "://invalid"); err == nil {
		t.Fatal("invalid URL was accepted")
	}
}

func TestExtractRejectsMalformedAndMissingArchives(t *testing.T) {
	for name, call := range map[string]func() error{
		"malformed zip": func() error { _, err := extractZIPFile([]byte("bad"), "tool"); return err },
		"missing zip":   func() error { _, err := extractZIPFile(zipArchive(t, "other", []byte("x")), "tool"); return err },
		"malformed tar": func() error { _, err := extractFile([]byte("bad"), "tool"); return err },
		"missing tar":   func() error { _, err := extractFile(tarGz(t, "other", []byte("x")), "tool"); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("malformed/missing archive was accepted")
			}
		})
	}
}

func TestInstallReleaseFailureBranchesLeaveNoPartialTarget(t *testing.T) {
	s := New(nil, quietLogger{})
	t.Run("unsupported architecture mapping", func(t *testing.T) {
		rel := release(t, "")
		rel.SHA256 = map[string]string{}
		if err := s.installRelease(context.Background(), "tool", rel); err == nil {
			t.Fatal("missing architecture checksum was accepted")
		}
	})

	t.Run("download failure", func(t *testing.T) {
		original := fetch
		fetch = func(context.Context, string) ([]byte, error) { return nil, errors.New("network down") }
		t.Cleanup(func() { fetch = original })
		rel := release(t, strings.Repeat("0", 64))
		if err := s.installRelease(context.Background(), "tool", rel); err == nil {
			t.Fatal("download failure was hidden")
		}
	})

	t.Run("valid checksum malformed archive", func(t *testing.T) {
		archive := []byte("not a tar archive")
		original := fetch
		fetch = func(context.Context, string) ([]byte, error) { return archive, nil }
		t.Cleanup(func() { fetch = original })
		rel := release(t, sum(archive))
		if err := s.installRelease(context.Background(), "tool", rel); err == nil {
			t.Fatal("malformed archive was installed")
		}
	})

	t.Run("target parent is a file", func(t *testing.T) {
		archive := tarGz(t, "dnsproxy", []byte("binary"))
		original := fetch
		fetch = func(context.Context, string) ([]byte, error) { return archive, nil }
		t.Cleanup(func() { fetch = original })
		parent := filepath.Join(t.TempDir(), "parent")
		if err := os.WriteFile(parent, []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		rel := release(t, sum(archive))
		rel.Target = filepath.Join(parent, "tool")
		if err := s.installRelease(context.Background(), "tool", rel); err == nil {
			t.Fatal("invalid target parent was accepted")
		}
	})

	t.Run("rename over directory", func(t *testing.T) {
		archive := tarGz(t, "dnsproxy", []byte("binary"))
		original := fetch
		fetch = func(context.Context, string) ([]byte, error) { return archive, nil }
		t.Cleanup(func() { fetch = original })
		rel := release(t, sum(archive))
		if err := os.Mkdir(rel.Target, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := s.installRelease(context.Background(), "tool", rel); err == nil {
			t.Fatal("directory target was replaced")
		}
		if _, err := os.Stat(rel.Target + ".new"); !os.IsNotExist(err) {
			t.Fatalf("partial target remains: %v", err)
		}
	})
}
