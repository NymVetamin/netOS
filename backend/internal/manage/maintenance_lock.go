package manage

import (
	"fmt"
	"os"
	"path/filepath"
)

func (m *Manager) lockMaintenance() (func(), error) {
	path := m.sys("/run/netos-maintenance.lock")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := tryMaintenanceLock(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("операция обслуживания уже выполняется или блокировка недоступна: %w", err)
	}
	// Do not unlink: another process may already hold a handle to this inode.
	// Closing releases the OS lock, including when the process exits abruptly.
	return func() { _ = file.Close() }, nil
}
