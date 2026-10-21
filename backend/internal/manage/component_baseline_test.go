package manage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/system"
)

func TestUninstallRejectsCorruptComponentRecoveryBeforeStoppingServices(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	dir := filepath.Join(m.sys(system.PackageOwnershipDir), "original-components")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	var calls []string
	m.Run = func(_ context.Context, c command) error { calls = append(calls, c.name); return nil }
	m.Output = func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, name)
		return "", nil
	}
	err := m.uninstallRun(context.Background(), false, false)
	if err == nil || !strings.Contains(err.Error(), "исходных компонентов") {
		t.Fatalf("error=%v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("host mutated before validation: %v", calls)
	}
}
