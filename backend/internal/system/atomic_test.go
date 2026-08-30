package system

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCleanupAtomicTempsOnlyRemovesRegularOwnedNames(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, ".tmp-123")
	keep := filepath.Join(dir, "important.tmp")
	if err := os.WriteFile(stale, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keep, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(keep, filepath.Join(dir, ".tmp-link")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, ".tmp-dir"), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := CleanupAtomicTemps(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale regular file remains: %v", err)
	}
	for _, path := range []string{keep, filepath.Join(dir, ".tmp-dir")} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("%s was removed: %v", path, err)
		}
	}
	if runtime.GOOS != "windows" {
		if _, err := os.Lstat(filepath.Join(dir, ".tmp-link")); err != nil {
			t.Fatalf("symlink was removed: %v", err)
		}
	}
}

func TestCleanupAtomicTempsAllowsMissingDirectory(t *testing.T) {
	if err := CleanupAtomicTemps(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatal(err)
	}
}
