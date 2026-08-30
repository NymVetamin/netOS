package api

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/system"
)

type BackupInfo struct {
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

type Maintenance struct {
	Runner    system.Runner
	BackupDir string
	Binary    string
	Unit      string
}

func NewMaintenance(r system.Runner) *Maintenance {
	return &Maintenance{Runner: r, BackupDir: "/var/backups/netos", Binary: "/usr/local/bin/netos", Unit: "netos-maintenance"}
}

func (m *Maintenance) Backups() ([]BackupInfo, error) {
	entries, err := os.ReadDir(m.BackupDir)
	if os.IsNotExist(err) {
		return []BackupInfo{}, nil
	}
	if err != nil {
		return nil, err
	}
	result := make([]BackupInfo, 0, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !validBackupName(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		result = append(result, BackupInfo{Name: entry.Name(), Size: info.Size(), Modified: info.ModTime()})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Modified.After(result[j].Modified) })
	return result, nil
}

func (m *Maintenance) BackupPath(name string) (string, error) {
	if !validBackupName(name) {
		return "", fmt.Errorf("некорректное имя резервной копии")
	}
	path := filepath.Join(m.BackupDir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("резервная копия не является обычным файлом")
	}
	return path, nil
}

var versionPattern = regexp.MustCompile(`^(?:latest|v?[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.-]+)?)$`)

func (m *Maintenance) Schedule(ctx context.Context, operation, argument string) error {
	active, _ := m.Runner.Run(ctx, "systemctl", "is-active", m.Unit+".service", m.Unit+".timer")
	for _, state := range strings.Fields(active) {
		if state == "active" || state == "activating" {
			return fmt.Errorf("операция обслуживания уже выполняется")
		}
	}
	var command []string
	switch operation {
	case "backup":
		command = []string{m.Binary, "backup"}
	case "restore":
		path, err := m.BackupPath(argument)
		if err != nil {
			return err
		}
		command = []string{m.Binary, "restore", path, "--yes"}
	case "update":
		if argument == "" {
			argument = "latest"
		}
		if !versionPattern.MatchString(argument) {
			return fmt.Errorf("некорректная версия")
		}
		command = []string{m.Binary, "update", argument}
	default:
		return fmt.Errorf("неизвестная операция обслуживания")
	}
	_, _ = m.Runner.Run(ctx, "systemctl", "reset-failed", m.Unit+".service")
	args := []string{
		"--quiet", "--unit=" + m.Unit, "--on-active=2s",
		"--property=Description=netOS-maintenance",
		"--property=StandardOutput=journal", "--property=StandardError=journal",
	}
	args = append(args, command...)
	if _, err := m.Runner.Run(ctx, "systemd-run", args...); err != nil {
		return fmt.Errorf("планирование обслуживания: %w", err)
	}
	return nil
}

func (m *Maintenance) Status(ctx context.Context) map[string]any {
	out, err := m.Runner.Run(ctx, "systemctl", "show", m.Unit+".service",
		"--property=ActiveState", "--property=SubState", "--property=Result", "--property=ExecMainStatus")
	if err != nil {
		return map[string]any{"state": "idle"}
	}
	fields := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			fields[key] = value
		}
	}
	state := fields["ActiveState"]
	if state == "" {
		state = "idle"
	}
	return map[string]any{
		"state": state, "sub_state": fields["SubState"], "result": fields["Result"], "exit_code": fields["ExecMainStatus"],
	}
}

func validBackupName(name string) bool {
	return strings.HasPrefix(name, "netos-") && strings.HasSuffix(name, ".tar.gz") &&
		filepath.Base(name) == name && !strings.ContainsAny(name, `/\\`) && len(name) <= 128
}
