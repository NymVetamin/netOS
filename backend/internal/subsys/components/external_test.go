package components

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("файл не исполняемый: %v", info.Mode())
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
