package system

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
)

func AmneziaWGUnitName(name string) string { return "netos-" + name + ".service" }

// RenderAmneziaWGUnit restores a complete tunnel on every process restart.
// Peer edits only change conf and are synchronized without restarting this unit.
func RenderAmneziaWGUnit(name, conf, address string, mtu, table int, disableIPv6 bool) ([]byte, error) {
	prefix := "awg-ch"
	if strings.HasPrefix(name, "awg-srv") {
		prefix = "awg-srv"
	}
	index, err := strconv.Atoi(strings.TrimPrefix(name, prefix))
	if err != nil || index < 1 || name != prefix+strconv.Itoa(index) || len(name) > 15 {
		return nil, fmt.Errorf("некорректное имя AmneziaWG")
	}
	addr, err := netip.ParsePrefix(address)
	if err != nil || !addr.Addr().Is4() || mtu < 576 || mtu > 65535 || table < 0 {
		return nil, fmt.Errorf("некорректные параметры интерфейса AmneziaWG")
	}
	// Systemd expands %, $, quotes and escapes even without a shell. Generated
	// paths need none of them; reject instead of introducing a second parser.
	if !strings.HasPrefix(conf, "/") || strings.ContainsAny(conf, "\r\n\t \"'\\%$") {
		return nil, fmt.Errorf("некорректный путь конфигурации AmneziaWG")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Unit]\nDescription=netOS AmneziaWG %s\nAfter=network.target\n\n[Service]\nType=notify\nNotifyAccess=main\nExecStart=/usr/local/bin/netosd amneziawg serve %s\n", name, name)
	fmt.Fprintf(&b, "ExecStartPost=/usr/local/bin/netosd amneziawg syncconf %s %s\n", name, conf)
	if disableIPv6 {
		fmt.Fprintf(&b, "ExecStartPost=/usr/sbin/sysctl -w net.ipv6.conf.%s.disable_ipv6=1\n", name)
	}
	fmt.Fprintf(&b, "ExecStartPost=/usr/sbin/ip -4 addr replace %s dev %s\nExecStartPost=/usr/sbin/ip link set dev %s mtu %d up\n", address, name, name, mtu)
	if table != 0 {
		fmt.Fprintf(&b, "ExecStartPost=/usr/sbin/ip -4 route replace default dev %s metric 100 table %d proto 201\n", name, table)
	}
	b.WriteString("Restart=on-failure\nRestartSec=2\nTimeoutStartSec=30\nTimeoutStopSec=10\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\nProtectSystem=full\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE\n\n[Install]\nWantedBy=multi-user.target\n")
	return []byte(b.String()), nil
}

// EnsureAmneziaWGService only restarts for unit changes or an inactive service.
// Configuration validation and transaction rollback belong to the caller.
func EnsureAmneziaWGService(ctx context.Context, r Runner, unitDir, name string, unit []byte) error {
	path := filepath.Join(unitDir, AmneziaWGUnitName(name))
	restart := UnitRuntimeChanged(path, unit)
	changed, err := WriteFileAtomicIfChanged(path, unit, 0o644)
	if err != nil {
		return err
	}
	if changed {
		if _, err := r.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	service := AmneziaWGUnitName(name)
	enabled, _ := r.Run(ctx, "systemctl", "is-enabled", service)
	if strings.TrimSpace(enabled) != "enabled" {
		if _, err := r.Run(ctx, "systemctl", "enable", service); err != nil {
			return err
		}
	}
	active, _ := r.Run(ctx, "systemctl", "is-active", service)
	if restart || strings.TrimSpace(active) != "active" {
		_, err = r.Run(ctx, "systemctl", "restart", service)
	}
	return err
}
