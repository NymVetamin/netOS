package manage

import (
	"context"
	"fmt"
	"github.com/netos-router/netos/internal/subsys/services"
)

func (m *Manager) prepareRestoreResolver(ctx context.Context) error {
	resolved, err := services.RestoreSystemResolverFiles(m.Root)
	if err != nil {
		return fmt.Errorf("восстановление системного DNS перед restore: %w", err)
	}
	if resolved {
		if err := m.run(ctx, "systemctl", "enable", "--now", "systemd-resolved.service"); err != nil {
			return fmt.Errorf("запуск системного DNS перед restore: %w", err)
		}
	}
	return nil
}
