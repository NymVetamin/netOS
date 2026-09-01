package api

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
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
	file, err := m.OpenBackup(filepath.Base(good))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(file)
	_ = file.Close()
	if err != nil || string(data) != "archive" {
		t.Fatalf("opened backup = %q, err=%v", data, err)
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(dir, "netos-link.tar.gz")
		if err := os.Symlink(good, link); err != nil {
			t.Fatal(err)
		}
		if _, err := m.OpenBackup(filepath.Base(link)); err == nil {
			t.Fatal("backup symlink was accepted")
		}
	}
	if err := m.Schedule(context.Background(), "restore", filepath.Base(good)); err != nil {
		t.Fatal(err)
	}
	if err := m.SchedulePanelActivation(context.Background(), 12, 7); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "systemd-run --quiet --unit=netos-maintenance --on-active=2s") || !strings.Contains(joined, good+" --yes") ||
		!strings.Contains(joined, "/usr/local/bin/netos internal-panel-activate 12 7") {
		t.Fatalf("unexpected schedule:\n%s", joined)
	}
	if err := m.DeleteBackup(filepath.Base(good)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(good); !os.IsNotExist(err) {
		t.Fatalf("backup still exists after delete: %v", err)
	}
}

func TestMaintenanceRejectsUnsafeVersion(t *testing.T) {
	m := &Maintenance{Runner: &maintenanceRunner{}, Binary: "/usr/local/bin/netos", Unit: "netos-maintenance"}
	for _, value := range []string{"master", "v1;reboot", "../v1.2"} {
		if err := m.Schedule(context.Background(), "update", value); err == nil {
			t.Errorf("unsafe version accepted: %q", value)
		}
	}
	for _, revisions := range [][2]int64{{0, 1}, {1, 0}, {2, 2}} {
		if err := m.SchedulePanelActivation(context.Background(), revisions[0], revisions[1]); err == nil {
			t.Errorf("invalid panel revisions accepted: %v", revisions)
		}
	}
}
