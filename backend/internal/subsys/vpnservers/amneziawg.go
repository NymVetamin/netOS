package vpnservers

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func amneziaServerUnit(server config.VPNServer) string {
	if server.Type == "amneziawg" {
		return system.AmneziaWGUnitName(InterfaceName(server))
	}
	return ""
}

func (s *Subsystem) applyAmneziaWG(ctx context.Context, server config.VPNServer, owned, disableIPv6 bool) (created bool, retErr error) {
	name := InterfaceName(server)
	if s.linkExists(name) && !owned {
		return false, fmt.Errorf("интерфейс %s не принадлежит netOS", name)
	}
	files, err := capturePaths(filepath.Join(s.StateDir, name+".conf"), filepath.Join(s.UnitDir, amneziaServerUnit(server)))
	if err != nil {
		return false, err
	}
	defer func() {
		if retErr == nil {
			return
		}
		rollback := context.Background()
		if !owned {
			if err := s.remove(rollback, ownedServer{Name: name, Index: server.Index, Type: server.Type, Unit: amneziaServerUnit(server)}); err != nil {
				retErr = fmt.Errorf("%v; cleanup: %w", retErr, err)
			}
			return
		}
		if err := restorePaths(files); err != nil {
			retErr = fmt.Errorf("%v; rollback: %w", retErr, err)
			return
		}
		if _, err := s.Runner.Run(rollback, "systemctl", "daemon-reload"); err != nil {
			retErr = fmt.Errorf("%v; rollback: %w", retErr, err)
			return
		}
		if _, err := s.Runner.Run(rollback, "systemctl", "restart", amneziaServerUnit(server)); err != nil {
			retErr = fmt.Errorf("%v; rollback: %w", retErr, err)
		}
	}()
	return s.applyWireGuard(ctx, server, owned, disableIPv6)
}
