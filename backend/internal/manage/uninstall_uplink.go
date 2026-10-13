package manage

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// A host route protects the SSH return path without making waitDefaultRoute
// mistake our temporary protection for a restored OS default route.
type uninstallSSHRoute struct {
	Destination string `json:"dst"`
	Gateway     string `json:"gateway"`
	Device      string `json:"dev"`
	Protocol    string `json:"protocol"`
	Metric      int    `json:"metric"`
}

func (r uninstallSSHRoute) args(action string) []string {
	args := []string{"-4", "route", action, r.Destination}
	if r.Gateway != "" {
		args = append(args, "via", r.Gateway)
	}
	return append(args, "dev", r.Device, "proto", "boot", "metric", "42760")
}

func (m *Manager) protectUninstallSSH(ctx context.Context, uplink managementUplink) (func() error, error) {
	// A retry from a local console still owns the route left by its earlier
	// SSH attempt and must remove it on successful completion.
	noop := func() error { return m.releasePreviousUninstallSSH(ctx) }
	if m.Getenv == nil {
		return noop, nil
	}
	parts := strings.Fields(m.Getenv("SSH_CONNECTION"))
	if len(parts) != 4 {
		return noop, nil
	}
	peer, err := netip.ParseAddr(parts[0])
	if err != nil || !peer.Is4() || uplink.device == "" {
		return noop, nil
	}
	address, err := netip.ParsePrefix(uplink.address)
	if err != nil {
		return nil, err
	}
	route := uninstallSSHRoute{Destination: peer.String() + "/32", Device: uplink.device, Protocol: "boot", Metric: 42760}
	if !address.Contains(peer) {
		for i, field := range uplink.route {
			if field == "via" && i+1 < len(uplink.route) {
				route.Gateway = uplink.route[i+1]
			}
		}
		if route.Gateway == "" {
			return nil, fmt.Errorf("не определён шлюз для сохранения SSH")
		}
	}
	// Keep ownership across a failed uninstall. Never replace a conflicting
	// route, or adopt an existing route without our persisted ownership record.
	marker := m.sys(systemBaselineDir + "/uninstall-ssh-route.json")
	data, readErr := os.ReadFile(marker)
	var owned uninstallSSHRoute
	if readErr == nil {
		if err := json.Unmarshal(data, &owned); err != nil {
			return nil, fmt.Errorf("сохранённый путь SSH повреждён; удаление остановлено до изменений")
		}
		if owned != route {
			// The administrator may reconnect from another address. Remove only
			// our verified previous protection, then establish the new one before
			// stopping services or flushing any routes.
			if err := m.releasePreviousUninstallSSH(ctx); err != nil {
				return nil, err
			}
			readErr = os.ErrNotExist
		}
	} else if !os.IsNotExist(readErr) {
		return nil, readErr
	}
	out, err := m.Output(ctx, "ip", "-j", "-4", "route", "show", "table", "main", "exact", route.Destination)
	if err != nil {
		return nil, err
	}
	var existing []uninstallSSHRoute
	if err := json.Unmarshal([]byte(out), &existing); err != nil {
		return nil, fmt.Errorf("чтение маршрута SSH: %w", err)
	}
	found := false
	for _, candidate := range existing {
		// iproute2 omits its default protocol (boot) from JSON output.
		if candidate.Protocol == "" {
			candidate.Protocol = "boot"
		}
		// iproute2 may omit /32 when printing a host destination.
		if candidate.Destination == peer.String() {
			candidate.Destination += "/32"
		}
		if candidate.Metric == route.Metric {
			if candidate != route || readErr != nil {
				return nil, fmt.Errorf("временный путь SSH конфликтует с существующим маршрутом")
			}
			found = true
		}
	}
	if !found {
		if err := os.MkdirAll(filepath.Dir(marker), 0700); err != nil {
			return nil, err
		}
		data, _ := json.Marshal(route)
		if err := os.WriteFile(marker, data, 0600); err != nil {
			return nil, err
		}
		if err := m.run(ctx, "ip", route.args("add")...); err != nil {
			return nil, fmt.Errorf("сохранение пути SSH: %w", err)
		}
	}
	return func() error {
		if err := m.run(ctx, "ip", route.args("del")...); err != nil {
			return fmt.Errorf("удаление временного пути SSH: %w", err)
		}
		if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}, nil
}

func (m *Manager) releasePreviousUninstallSSH(ctx context.Context) error {
	marker := m.sys(systemBaselineDir + "/uninstall-ssh-route.json")
	data, err := os.ReadFile(marker)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var owned uninstallSSHRoute
	if err := json.Unmarshal(data, &owned); err != nil {
		return err
	}
	dst, err := netip.ParsePrefix(owned.Destination)
	if err != nil || !dst.Addr().Is4() || dst.Bits() != 32 || !validLinkName(owned.Device) || owned.Protocol != "boot" || owned.Metric != 42760 {
		return fmt.Errorf("некорректная запись временного пути SSH")
	}
	out, err := m.Output(ctx, "ip", "-j", "-4", "route", "show", "table", "main", "exact", owned.Destination)
	if err != nil {
		return err
	}
	var routes []uninstallSSHRoute
	if err := json.Unmarshal([]byte(out), &routes); err != nil {
		return err
	}
	for _, route := range routes {
		if route.Destination == dst.Addr().String() {
			route.Destination += "/32"
		}
		if route.Protocol == "" {
			route.Protocol = "boot"
		}
		if route.Metric != owned.Metric {
			continue
		}
		if route != owned {
			return fmt.Errorf("прежний временный путь SSH изменён; чужой маршрут сохранён")
		}
		if err := m.run(ctx, "ip", owned.args("del")...); err != nil {
			return err
		}
	}
	return os.Remove(marker)
}
