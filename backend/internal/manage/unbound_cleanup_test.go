package manage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestUninstallRemovesOnlyOwnedUnboundFiles(t *testing.T) {
	for _, keep := range []bool{false, true} {
		t.Run(fmt.Sprint(keep), func(t *testing.T) {
			m, _ := testManager()
			sandbox(t, m)
			owned := []string{"/etc/unbound/netos.conf", "/etc/unbound/netos-blocklist.conf"}
			anchors := []string{"/var/lib/unbound/netos-root.key", "/var/lib/unbound/netos/root.key", "/var/lib/unbound/netos/root.key.123-tmp"}
			foreign := []string{"/etc/unbound/unbound.conf", "/var/lib/unbound/root.key"}
			for _, name := range append(append(append([]string{}, owned...), anchors...), foreign...) {
				path := m.sys(name)
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := m.uninstall(context.Background(), true, keep, false, true); err != nil {
				t.Fatal(err)
			}
			for _, name := range owned {
				if _, err := os.Stat(m.sys(name)); !os.IsNotExist(err) {
					t.Fatalf("retained %s: %v", name, err)
				}
			}
			for _, anchor := range anchors {
				_, err := os.Stat(m.sys(anchor))
				if keep && err != nil || !keep && !os.IsNotExist(err) {
					t.Fatalf("anchor %s keep=%v: %v", anchor, keep, err)
				}
			}
			for _, name := range foreign {
				if _, err := os.Stat(m.sys(name)); err != nil {
					t.Fatalf("removed foreign %s", name)
				}
			}
		})
	}
}
