package services

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveGeneratedDeletesOnlyNamedFiles(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "old.conf")
	second := filepath.Join(dir, "old-hosts")
	keep := filepath.Join(dir, "active.conf")
	for _, path := range []string{first, second, keep} {
		if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := removeGenerated(first, second, filepath.Join(dir, "already-gone")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{first, second} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("stale file remains: %s", path)
		}
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("active file was removed: %v", err)
	}
}
