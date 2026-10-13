package manage

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// No --pipe/--pty/--scope: the worker and all its children belong to PID 1,
// with journal output and null stdin, never to the initiating SSH session.
func (m *Manager) launchUninstall(ctx context.Context, keepData, backup bool) error {
	args := []string{"--unit=netos-uninstall", "--collect", "--wait", "--service-type=exec",
		"--property=StandardInput=null", "--property=StandardOutput=journal", "--property=StandardError=journal",
		"--setenv=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	if m.Getenv != nil {
		if connection := m.Getenv("SSH_CONNECTION"); connection != "" {
			args = append(args, "--setenv=SSH_CONNECTION="+connection)
		}
	}
	args = append(args, "--", m.CLI, "internal-uninstall")
	if keepData {
		args = append(args, "--keep-data")
	}
	if backup {
		args = append(args, "--backup")
	} else {
		args = append(args, "--no-backup")
	}
	fmt.Fprintf(m.Out, "Удаление будет выполняться отдельной службой и продолжится при разрыве SSH. Журнал: %s\n", uninstallLogPath)
	if err := m.run(ctx, "systemd-run", args...); err != nil {
		return fmt.Errorf("запуск или выполнение удаления завершилось ошибкой: %w; журнал: %s; журнал службы: journalctl -u netos-uninstall", err, uninstallLogPath)
	}
	fmt.Fprintln(m.Out, "netOS удалён.")
	return nil
}

// DHCP can temporarily install an IPv4LL default with no gateway. It is not
// evidence of restored uplink connectivity. Gatewayless PPP routes remain valid.
func usableDefaultRoute(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "default" {
			continue
		}
		dev, invalid := false, false
		for i, field := range fields {
			if field == "linkdown" || field == "dead" {
				invalid = true
			}
			if i+1 >= len(fields) {
				continue
			}
			if field == "dev" {
				dev = fields[i+1] != "lo"
			}
			if field == "src" || field == "via" {
				addr, err := netip.ParseAddr(fields[i+1])
				if err != nil || !addr.Is4() || !addr.IsGlobalUnicast() || addr.IsLinkLocalUnicast() {
					invalid = true
				}
			}
		}
		if dev && !invalid {
			return true
		}
	}
	return false
}
