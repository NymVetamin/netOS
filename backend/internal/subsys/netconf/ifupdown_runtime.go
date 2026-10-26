package netconf

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/netos-router/netos/internal/config"
)

var ifupdownStatePath = "/run/network/ifstate"

// Instance escaping follows systemd's non-path escaping. In particular a dash
// in an interface name is not the slash represented by an unescaped dash.
func ifupUnit(name string) string {
	var b strings.Builder
	b.WriteString("ifup@")
	for i, c := range []byte(name) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == ':' || (c == '.' && i != 0) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "\\x%02x", c)
		}
	}
	b.WriteString(".service")
	return b.String()
}

// Both sources matter: auto links may belong to networking.service, while
// hotplug links run in independent ifup@ instances even with networking off.
func (s *Subsystem) liveIfupdown(ctx context.Context) (map[string]bool, map[string]bool, error) {
	registered, active := map[string]bool{}, map[string]bool{}
	data, err := os.ReadFile(ifupdownStatePath)
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		name, _, ok := strings.Cut(line, "=")
		if ok {
			registered[name] = true
		}
	}
	out, err := s.Runner.Run(ctx, "systemctl", "list-units", "--all", "--plain", "--no-legend", "--full", "ifup@*.service")
	if err != nil {
		return nil, nil, fmt.Errorf("проверка hotplug-служб ifupdown: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[2] != "inactive" && fields[2] != "failed" {
			active[fields[0]] = true
		}
	}
	return registered, active, nil
}

func (s *Subsystem) releaseIfupdown(ctx context.Context, cfg *config.Config) error {
	registered, active, err := s.liveIfupdown(ctx)
	if err != nil {
		return err
	}
	for _, name := range managedInterfaces(cfg) {
		unit := ifupUnit(name)
		if active[unit] {
			if _, err := s.Runner.Run(ctx, "systemctl", "stop", unit); err != nil {
				return fmt.Errorf("остановка %s: %w", unit, err)
			}
		} else if registered[name] {
			if _, err := s.Runner.Run(ctx, "ifdown", name); err != nil {
				return fmt.Errorf("освобождение интерфейса %s от ifupdown: %w", name, err)
			}
		}
	}
	return s.ifupdownRuntimeHealth(ctx, cfg)
}

// In the ifupdown backend, generated LAN stanzas legitimately remain active.
// Only owners of foreign stanzas being replaced need to release their leases.
func (s *Subsystem) releaseForeignIfupdown(ctx context.Context, cfg *config.Config) error {
	files, _, err := ifupdownInputs(os.ReadFile)
	if err != nil {
		return err
	}
	selected := *cfg
	selected.Interfaces = nil
	for _, iface := range cfg.Interfaces {
		for _, data := range files {
			if mentionsInterface(string(data), iface.Name) {
				selected.Interfaces = append(selected.Interfaces, iface)
				break
			}
		}
	}
	if len(selected.Interfaces) == 0 {
		return nil
	}
	return s.releaseIfupdown(ctx, &selected)
}

func (s *Subsystem) ifupdownRuntimeHealth(ctx context.Context, cfg *config.Config) error {
	registered, active, err := s.liveIfupdown(ctx)
	if err != nil {
		return err
	}
	for _, name := range managedInterfaces(cfg) {
		if registered[name] || active[ifupUnit(name)] {
			return fmt.Errorf("интерфейс %s остаётся под управлением ifupdown", name)
		}
	}
	return nil
}

func (s *Subsystem) ifupdownOwnershipHealth(ctx context.Context, cfg *config.Config) error {
	files, _, err := ifupdownInputs(os.ReadFile)
	if err != nil {
		return err
	}
	for path, data := range files {
		for _, name := range managedInterfaces(cfg) {
			if mentionsInterface(string(data), name) {
				return fmt.Errorf("%s продолжает настраивать интерфейс %s через ifupdown", path, name)
			}
		}
	}
	return s.ifupdownRuntimeHealth(ctx, cfg)
}
