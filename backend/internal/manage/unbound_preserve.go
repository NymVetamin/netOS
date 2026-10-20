package manage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/netos-router/netos/internal/system"
)

// Debian's unbound postrm removes /var/lib/unbound, including our anchor.
// Keep a durable copy outside that tree until the package operation completes.
// A retry can recover this copy even if the preceding process was interrupted.
type keptUnboundData struct {
	Legacy []byte            `json:"legacy,omitempty"`
	Files  map[string][]byte `json:"files"`
}

func (m *Manager) removePackagesPreservingUnbound(ctx context.Context, keep bool) error {
	if !keep {
		return m.removeInstalledPackages(ctx)
	}
	snapshot := filepath.Join(m.StateDir, "uninstall-unbound.json")
	data := keptUnboundData{Files: map[string][]byte{}}
	if raw, err := os.ReadFile(snapshot); err == nil {
		if err := json.Unmarshal(raw, &data); err != nil {
			return fmt.Errorf("сохранённые данные Unbound: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if data.Files == nil {
		data.Files = map[string][]byte{}
	}
	legacy := m.sys("/var/lib/unbound/netos-root.key")
	if raw, err := readKeptUnboundFile(legacy); err == nil {
		data.Legacy = raw
	} else if !os.IsNotExist(err) {
		return err
	}
	dir := m.sys("/var/lib/unbound/netos")
	if info, err := os.Lstat(dir); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("каталог состояния Unbound %s не является каталогом", dir)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			raw, err := readKeptUnboundFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				return err
			}
			data.Files[entry.Name()] = raw
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	for name := range data.Files {
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
			return fmt.Errorf("недопустимое имя сохранённого файла Unbound")
		}
	}
	if data.Legacy == nil && len(data.Files) == 0 {
		return m.removeInstalledPackages(ctx)
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(m.StateDir, 0700); err != nil {
		return err
	}
	if err := system.WriteFileAtomic(snapshot, raw, 0600); err != nil {
		return err
	}
	purgeErr := m.removeInstalledPackages(ctx)
	if err := restoreKeptUnbound(data, legacy, dir); err != nil {
		return errors.Join(purgeErr, fmt.Errorf("восстановление Unbound; копия сохранена в %s: %w", snapshot, err))
	}
	return errors.Join(purgeErr, os.Remove(snapshot))
}

func readKeptUnboundFile(name string) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("файл состояния Unbound %s не является обычным файлом", name)
	}
	return os.ReadFile(name)
}

func restoreKeptUnbound(data keptUnboundData, legacy, dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0755); err != nil {
		return err
	}
	if data.Legacy != nil {
		if err := system.WriteFileAtomic(legacy, data.Legacy, 0600); err != nil {
			return err
		}
	}
	if len(data.Files) == 0 {
		return nil
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s не является каталогом", dir)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	for name, raw := range data.Files {
		if err := system.WriteFileAtomic(filepath.Join(dir, name), raw, 0600); err != nil {
			return err
		}
	}
	return nil
}
