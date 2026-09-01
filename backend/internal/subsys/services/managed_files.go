package services

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/netos-router/netos/internal/system"
)

var systemdUnitDir = "/etc/systemd/system"

// writeManagedFile changes bytes only when necessary. A permission-only drift
// is repaired without replacing the inode or forcing a daemon restart.
func writeManagedFile(path string, content []byte, mode os.FileMode) (bool, error) {
	changed := system.FileChanged(path, content)
	if changed {
		if err := system.WriteFileAtomic(path, content, mode); err != nil {
			return false, err
		}
		return true, nil
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			return false, err
		}
		if info.Mode().Perm() != mode.Perm() {
			if err := os.Chmod(path, mode); err != nil {
				return false, err
			}
		}
	}
	return false, nil
}

func managedFileHealth(path string, content []byte, mode os.FileMode) error {
	if system.FileChanged(path, content) {
		return fmt.Errorf("содержимое %s не соответствует конфигурации", path)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("проверка %s: %w", path, err)
		}
		if info.Mode().Perm() != mode.Perm() {
			return fmt.Errorf("режим %s равен %o, ожидался %o", path, info.Mode().Perm(), mode.Perm())
		}
	}
	return nil
}

func generatedAbsent(path string) error {
	_, err := os.Stat(path)
	if err == nil {
		return fmt.Errorf("остался неиспользуемый generated-файл %s", path)
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("проверка %s: %w", path, err)
	}
	return nil
}

func managedFileModeHealth(path string, mode os.FileMode, required bool) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) && !required {
		return nil
	}
	if err != nil {
		return fmt.Errorf("проверка %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s не является обычным файлом", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("режим %s равен %o, ожидался %o", path, info.Mode().Perm(), mode.Perm())
	}
	return nil
}

func validateManagedContent(path string, content []byte, mode os.FileMode, validate func(string) error) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".netos-validate-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return validate(tmp)
}
