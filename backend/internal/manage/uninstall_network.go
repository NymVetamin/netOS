package manage

import (
	"context"
	"fmt"
	"strings"
)

// Stop sockets before services so they cannot reactivate a manager being
// returned to its pre-install inactive state.
var networkBaselineUnits = []string{"systemd-networkd.socket", "systemd-networkd.service", "networking.service"}

func serviceWasActive(state serviceBaseline) bool {
	return state.Active == "active" || state.Active == "activating" || state.Active == "reloading"
}

// Generated network files have already been removed and original ifupdown
// files restored. Only now may the previous network owner read its config.
func (m *Manager) restoreOriginalNetworkServices(ctx context.Context, b *systemBaseline) (bool, error) {
	if b == nil || len(b.NetworkServices) == 0 {
		// Old baselines did not record the manager. Query the surviving original
		// ifupdown configuration, not the backend netOS happened to use last.
		out, err := m.Output(ctx, "ifquery", "--list")
		if err != nil {
			return false, nil
		}
		configured := false
		for _, name := range strings.Fields(out) {
			if name != "lo" {
				configured = true
			}
		}
		if !configured {
			return false, nil
		}
		fmt.Fprintln(m.Out, "Возвращаем сеть исходной конфигурации /etc/network/interfaces…")
		if err := m.run(ctx, "systemctl", "unmask", "networking.service"); err != nil {
			return true, err
		}
		if err := m.run(ctx, "systemctl", "enable", "networking.service"); err != nil {
			return true, err
		}
		if err := m.run(ctx, "systemctl", "start", "networking.service"); err != nil {
			return true, err
		}
		return true, m.startOriginalIfupdownLinks(ctx)
	}

	fmt.Fprintln(m.Out, "Восстанавливаем исходные службы управления сетью…")
	// Release former owners before starting the original one.
	for _, active := range []bool{false, true} {
		for _, unit := range networkBaselineUnits {
			state, exists := b.NetworkServices[unit]
			if !exists || serviceWasActive(state) != active {
				continue
			}
			if state.Enabled != "masked" && state.Enabled != "masked-runtime" {
				load, err := m.Output(ctx, "systemctl", "show", "--property=LoadState", "--value", unit)
				if err != nil {
					return true, err
				}
				if strings.TrimSpace(load) == "not-found" && !active {
					continue
				}
				if err := m.run(ctx, "systemctl", "unmask", unit); err != nil {
					return true, err
				}
				if state.Enabled == "not-found" {
					state.Enabled = "disabled"
				}
			}
			if err := m.restoreServiceBaseline(ctx, unit, state); err != nil {
				return true, fmt.Errorf("%s: %w", unit, err)
			}
		}
	}
	if serviceWasActive(b.NetworkServices["networking.service"]) {
		if err := m.startOriginalIfupdownLinks(ctx); err != nil {
			return true, err
		}
	}
	for _, name := range b.IfupdownInterfaces {
		if !validLinkName(name) || strings.HasPrefix(name, "-") {
			return true, fmt.Errorf("некорректный исходный интерфейс %q", name)
		}
		if err := m.run(ctx, "ifup", name); err != nil {
			return true, fmt.Errorf("восстановление исходного интерфейса %s: %w", name, err)
		}
	}
	return true, nil
}

func (m *Manager) startOriginalIfupdownLinks(ctx context.Context) error {
	// `systemctl start networking` alone may skip allow-hotplug interfaces on
	// a running machine: no new udev event arrives after netOS releases them.
	if err := m.run(ctx, "ifup", "-a"); err != nil {
		return fmt.Errorf("подъём исходных auto-интерфейсов: %w", err)
	}
	if err := m.run(ctx, "ifup", "-a", "--allow=hotplug"); err != nil {
		return fmt.Errorf("подъём исходных hotplug-интерфейсов: %w", err)
	}
	return nil
}
