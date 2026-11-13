package manage

import (
	"context"
	"path/filepath"
	"testing"
)

func TestXrayLogCommandRejectsInvalidArgumentsAndNonRoot(t *testing.T) {
	for _, args := range [][]string{nil, {"run"}, {"bad", "/config.json"}, {"run", "relative.json"}, {"run", "/config.json", "extra"}} {
		m, _ := testManager()
		if err := m.Execute(context.Background(), append([]string{"internal-xray-run"}, args...)); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	m, _ := testManager()
	m.EUID = func() int { return 1000 }
	if err := m.Execute(context.Background(), []string{"internal-xray-run", "run", filepath.Join(t.TempDir(), "config.json")}); err == nil {
		t.Fatal("non-root accepted")
	}
}

func TestXrayLogWorkerDoesNotHoldMaintenanceLock(t *testing.T) {
	m, _ := testManager()
	m.Root = t.TempDir()
	m.AcquireMaintenance = func() (func(), error) { t.Fatal("long-lived worker took maintenance lock"); return nil, nil }
	if err := m.Execute(context.Background(), []string{"internal-xray-run", "check", filepath.Join(m.Root, "config.json")}); err == nil {
		t.Fatal("missing executable accepted")
	}
}
