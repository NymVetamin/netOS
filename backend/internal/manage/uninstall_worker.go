package manage

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
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
	// The worker writes to the journal, not to this terminal; its result is
	// read back from the part of the log appended by this run only.
	var logStart int64
	if info, err := os.Stat(m.sys(uninstallLogPath)); err == nil {
		logStart = info.Size()
	}
	if err := m.run(ctx, "systemd-run", args...); err != nil {
		if reason := m.uninstallResult(logStart); reason != "" {
			return fmt.Errorf("удаление не выполнено: %s\nПодробности: %s", reason, uninstallLogPath)
		}
		return fmt.Errorf("запуск или выполнение удаления завершилось ошибкой: %w; журнал: %s; журнал службы: journalctl -u netos-uninstall", err, uninstallLogPath)
	}
	fmt.Fprintln(m.Out, "netOS удалён.")
	return nil
}

// uninstallResult returns the error the worker recorded in the log after
// offset start, or "" when this run recorded none (it crashed or succeeded).
// A truncated log is read from its beginning.
func (m *Manager) uninstallResult(start int64) string {
	f, err := os.Open(m.sys(uninstallLogPath))
	if err != nil {
		return ""
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || start < 0 {
		return ""
	}
	size := info.Size()
	if size < start {
		start = 0
	}
	const marker = " Завершение удаления: "
	buf := make([]byte, min(size-start, 32<<10))
	for end := size; end-start >= int64(len(marker)); {
		offset := max(start, end-int64(len(buf)))
		block := buf[:end-offset]
		if _, err := f.ReadAt(block, offset); err != nil {
			return ""
		}
		if i := bytes.LastIndex(block, []byte(marker)); i >= 0 {
			reason := block[i+len(marker):]
			if end != size {
				from := offset + int64(i+len(marker))
				reason = make([]byte, min(size-from, 4<<20))
				if _, err := f.ReadAt(reason, from); err != nil {
					return ""
				}
			}
			reason = bytes.TrimSpace(reason)
			if bytes.Equal(reason, []byte("<nil>")) {
				return ""
			}
			return string(reason)
		}
		// Include a marker that straddles the left edge of this block.
		end = offset + int64(len(marker)) - 1
	}
	return ""
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
