package channels

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/netos-router/netos/internal/amneziawg"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// syncWireGuard retains the kernel-selected source port across reconciliation.
// The portable stored configuration deliberately does not contain that port.
func (s *Subsystem) syncWireGuard(ctx context.Context, name, path string) error {
	if strings.HasPrefix(name, "awg-") {
		_, err := amneziawg.WireGuardControl(ctx, s.Runner, "amneziawg", "syncconf", name, path)
		return err
	}
	out, err := s.Runner.Run(ctx, "wg", "show", name, "listen-port")
	if err != nil {
		return fmt.Errorf("чтение порта WireGuard: %w", err)
	}
	port, err := strconv.ParseUint(strings.TrimSpace(out), 10, 16)
	if err != nil {
		return fmt.Errorf("некорректный порт WireGuard")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(data), "# Сгенерировано netOS.") || strings.Count(string(data), "[Interface]\n") != 1 {
		return fmt.Errorf("неизвестный формат конфигурации WireGuard")
	}
	data = []byte(strings.Replace(string(data), "[Interface]\n", fmt.Sprintf("[Interface]\nListenPort = %d\n", port), 1))
	f, err := os.CreateTemp(s.StateDir, ".wg-sync-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := system.EnsureWireGuardAppArmor(ctx, s.AppArmorDir, s.AppArmorProfiles, s.StateDir, s.Runner.Run); err != nil {
		return err
	}
	_, err = s.Runner.Run(ctx, "wg", "syncconf", name, f.Name())
	return err
}

func amneziaUnit(ch config.Channel) string {
	if ch.Type == "amneziawg" && ch.WireGuardPeer == nil {
		return system.AmneziaWGUnitName(InterfaceName(ch))
	}
	return ""
}
