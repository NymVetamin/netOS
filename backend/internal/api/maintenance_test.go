package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type maintenanceRunner struct{ commands []string }

func (r *maintenanceRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.commands = append(r.commands, name+" "+strings.Join(args, " "))
	if name == "systemctl" && len(args) > 0 && args[0] == "show" {
		return "ActiveState=inactive\nSubState=dead\nResult=success\nExecMainStatus=0\n", nil
	}
	return "inactive", nil
}
func (r *maintenanceRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestMaintenanceBackupPathsAndSchedule(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "netos-backup-20260830-120000.tar.gz")
	if err := os.WriteFile(good, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unrelated.tar.gz"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &maintenanceRunner{}
	m := &Maintenance{Runner: runner, BackupDir: dir, Binary: "/usr/local/bin/netos", Unit: "netos-maintenance"}
	backups, err := m.Backups()
	if err != nil || len(backups) != 1 || backups[0].Name != filepath.Base(good) {
		t.Fatalf("backups=%+v err=%v", backups, err)
	}
	if _, err := m.BackupPath("../netos-backup-20260830-120000.tar.gz"); err == nil {
		t.Fatal("path traversal was accepted")
	}
	if err := m.Schedule(context.Background(), "restore", filepath.Base(good)); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "systemd-run --quiet --unit=netos-maintenance --on-active=2s") || !strings.Contains(joined, good+" --yes") {
		t.Fatalf("unexpected schedule:\n%s", joined)
	}
}

func TestMaintenanceRejectsUnsafeVersion(t *testing.T) {
	m := &Maintenance{Runner: &maintenanceRunner{}, Binary: "/usr/local/bin/netos", Unit: "netos-maintenance"}
	for _, value := range []string{"master", "v1;reboot", "../v1.2"} {
		if err := m.Schedule(context.Background(), "update", value); err == nil {
			t.Errorf("unsafe version accepted: %q", value)
		}
	}
}
