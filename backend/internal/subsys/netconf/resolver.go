package netconf

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/netos-router/netos/internal/system"
)

var systemResolverPath = "/etc/resolv.conf"

func hasNameserver(content []byte) bool {
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if ip, err := netip.ParseAddr(fields[1]); err == nil && !ip.IsUnspecified() && !ip.IsMulticast() {
			return true
		}
	}
	return false
}

// DHCP client's stop hooks can erase resolv.conf when networking releases its
// interfaces. Preserve the existing DNS until an explicitly enabled netOS DNS
// provider takes over later in Apply. Never invent upstreams or overwrite DNS
// supplied by the new network owner. Also run on a failed handover.
func preserveSystemResolver(path string) (func() error, error) {
	noop := func() error { return nil }
	before, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return noop, nil
	}
	if err != nil {
		return nil, fmt.Errorf("чтение системного DNS перед сменой управления сетью: %w", err)
	}
	if !hasNameserver(before) {
		return noop, nil
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	link, _ := os.Readlink(path)
	return func() error {
		// Preserve a replacement symlink chosen by another owner as well.
		currentLink, _ := os.Readlink(path)
		if currentLink != link {
			return nil
		}
		current, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("чтение системного DNS после смены управления сетью: %w", err)
		}
		if hasNameserver(current) {
			return nil
		}
		if err := system.WriteFileAtomic(target, before, info.Mode().Perm()); err != nil {
			return fmt.Errorf("сохранение системного DNS при смене управления сетью: %w", err)
		}
		return nil
	}, nil
}
