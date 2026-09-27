package manage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/subsys/samba"
)

func ownedSambaUnits(t *testing.T, m *Manager) []string {
	t.Helper()
	dir := filepath.Join(m.StateDir, "generated")
	p := filepath.Join(dir, "samba", "volumes.json")
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`[{"id":"disk","uuid":"ABCD-1234","filesystem":"exfat","enabled":true}]`), 0600); err != nil {
		t.Fatal(err)
	}
	units, err := samba.OwnedMountUnits(dir)
	if err != nil {
		t.Fatal(err)
	}
	return units
}

func TestSambaCleanupStopsMountsAfterServiceAndPreservesData(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	owned := ownedSambaUnits(t, m)
	var calls []string
	m.Run = func(_ context.Context, c command) error {
		calls = append(calls, c.name+" "+strings.Join(c.args, " "))
		return nil
	}
	unitDir := m.sys("/etc/systemd/system")
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"netos-samba.service", owned[0], owned[1], "srv-netos-foreign.mount"} {
		if err := os.WriteFile(filepath.Join(unitDir, name), []byte("fixture"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	data := m.sys("/srv/netos/abc/keep.dat")
	_ = os.MkdirAll(filepath.Dir(data), 0755)
	_ = os.WriteFile(data, []byte("keep"), 0644)
	if err := m.removeComponentUnits(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 || !strings.Contains(calls[0], "netos-samba.service") || !strings.Contains(calls[1], owned[0]) || !strings.Contains(calls[2], owned[1]) {
		t.Fatalf("unsafe stop order: %v", calls)
	}
	if b, err := os.ReadFile(data); err != nil || string(b) != "keep" {
		t.Fatal("volume files changed")
	}
	if _, err := os.Stat(filepath.Join(unitDir, "srv-netos-foreign.mount")); err != nil {
		t.Fatal("foreign unit removed")
	}
}
func TestSambaCleanupDoesNotRemoveBusyMountUnit(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	owned := ownedSambaUnits(t, m)
	unit := m.sys("/etc/systemd/system/" + owned[1])
	_ = os.MkdirAll(filepath.Dir(unit), 0755)
	_ = os.WriteFile(unit, []byte("fixture"), 0644)
	m.Run = func(context.Context, command) error { return fmt.Errorf("device busy") }
	if err := m.removeComponentUnits(context.Background()); err == nil {
		t.Fatal("busy mount treated as clean")
	}
	if _, err := os.Stat(unit); err != nil {
		t.Fatal("lost recovery unit")
	}
}
