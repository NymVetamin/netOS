package manage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestComponentCleanupRemovesOwnedPPPHooks(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	dir := m.sys("/etc/ppp/ip-pre-up.d")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "netos-l2tp-srv30")
	if err := os.Symlink(filepath.Join(m.StateDir, "generated", "vpn-l2tp-srv30.pre-up"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	foreign := filepath.Join(dir, "netos-l2tp-srv31")
	if err := os.WriteFile(foreign, []byte("foreign"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.removeComponentUnits(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("owned hook remains after component cleanup: %v", err)
	}
	if data, err := os.ReadFile(foreign); err != nil || string(data) != "foreign" {
		t.Fatalf("foreign hook changed: %v %s", err, data)
	}
}
