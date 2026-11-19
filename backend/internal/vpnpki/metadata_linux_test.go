package vpnpki

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishRepairsFileMetadata(t *testing.T) {
	dir := t.TempDir()
	data := []byte("approved\n")
	path, other := filepath.Join(dir, "allowed"), filepath.Join(dir, "other")
	if err := os.WriteFile(other, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, link := range []func(string, string) error{os.Link, os.Symlink} {
		if err := link(other, path); err != nil {
			t.Fatal(err)
		}
		if err := publishStaticFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		a, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.Stat(other)
		if err != nil || !a.Mode().IsRegular() || os.SameFile(a, b) {
			t.Fatal("link was retained", err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	if err := publishStaticFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || !matchesPublishedMetadata(info, 0600) {
		t.Fatal("incorrect file metadata", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("incorrect file content", err)
	}
}
