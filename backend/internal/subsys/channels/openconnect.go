package channels

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func openConnectUnitName(ch config.Channel) string {
	return fmt.Sprintf("netos-openconnect-ch%d.service", ch.Index)
}

func (s *Subsystem) openConnectPaths(ch config.Channel) (conf, password, script, unit string) {
	base := filepath.Join(s.StateDir, fmt.Sprintf("openconnect-ch%d", ch.Index))
	return base + ".conf", base + ".password", base + "-script", filepath.Join(s.UnitDir, openConnectUnitName(ch))
}

func renderOpenConnect(ch config.Channel, oc config.OpenConnectChannelConfig, script string, disableIPv6 bool) string {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	line("# Сгенерировано netOS. Пароль хранится отдельно; права файла 0600.")
	line("server=%s", oc.Server)
	line("user=%s", oc.Username)
	line("protocol=%s", valueOr(oc.Protocol, "anyconnect"))
	line("interface=%s", InterfaceName(ch))
	line("script=%s", script)
	line("non-inter")
	line("syslog")
	if disableIPv6 {
		line("disable-ipv6")
	}
	if oc.AuthGroup != "" {
		line("authgroup=%s", oc.AuthGroup)
	}
	if oc.ServerCert != "" {
		line("servercert=%s", oc.ServerCert)
	}
	if oc.MTU > 0 {
		line("mtu=%d", oc.MTU)
	}
	if oc.NoDTLS {
		line("no-dtls")
	}
	if oc.NoSystemTrust {
		line("no-system-trust")
	}
	return b.String()
}

func renderOpenConnectScript(defaultMTU int) string {
	if defaultMTU == 0 {
		defaultMTU = 1400
	}
	return fmt.Sprintf(`#!/bin/sh
set -eu
case "${reason:-}" in
  connect|reconnect)
    prefix="${INTERNAL_IP4_NETMASKLEN:-32}"
    mtu="${INTERNAL_IP4_MTU:-%d}"
    ip link set dev "$TUNDEV" mtu "$mtu" up
    ip -4 addr flush dev "$TUNDEV"
    ip -4 addr add "$INTERNAL_IP4_ADDRESS/$prefix" dev "$TUNDEV"
    ;;
  disconnect)
    ;;
esac
`, defaultMTU)
}

func renderOpenConnectUnit(ch config.Channel, conf, password string) string {
	return `[Unit]
Description=netOS: OpenConnect-канал ` + ch.Name + `
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
StandardInput=file:` + password + `
ExecStart=/usr/sbin/openconnect --config=` + conf + ` --passwd-on-stdin
Restart=always
RestartSec=5
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
`
}

func (s *Subsystem) applyOpenConnect(ctx context.Context, ch config.Channel, wasOwned, disableIPv6 bool) (created bool, retErr error) {
	existedBefore := s.linkExists(InterfaceName(ch))
	if existedBefore && !wasOwned {
		return false, fmt.Errorf("интерфейс %s уже существует и не принадлежит netOS", InterfaceName(ch))
	}
	oc, err := ch.OpenConnectConfig()
	if err != nil {
		return false, err
	}
	confPath, passwordPath, scriptPath, unitPath := s.openConnectPaths(ch)
	snapshots, err := captureChannelFiles(confPath, passwordPath, scriptPath, unitPath)
	if err != nil {
		return false, err
	}
	mutated := false
	defer func() {
		if retErr == nil || !mutated {
			return
		}
		rollbackCtx := context.Background()
		if !wasOwned {
			s.cleanupOpenConnect(rollbackCtx, ch)
			_, _ = s.Runner.Run(rollbackCtx, "ip", "-4", "rule", "del", "priority", fmt.Sprint(Priority(ch)))
			_, _ = s.Runner.Run(rollbackCtx, "ip", "-4", "route", "flush", "table", fmt.Sprint(TableNumber(ch)))
			if s.linkExists(InterfaceName(ch)) {
				_, _ = s.Runner.Run(rollbackCtx, "ip", "link", "delete", InterfaceName(ch))
			}
			return
		}
		if err := restoreChannelFiles(snapshots); err != nil {
			retErr = fmt.Errorf("%v; rollback OpenConnect: %w", retErr, err)
			return
		}
		_, _ = s.Runner.Run(rollbackCtx, "systemctl", "daemon-reload")
		_, _ = s.Runner.Run(rollbackCtx, "systemctl", "restart", openConnectUnitName(ch))
	}()
	conf := []byte(renderOpenConnect(ch, oc, scriptPath, disableIPv6))
	password := []byte(oc.Password + "\n")
	script := []byte(renderOpenConnectScript(oc.MTU))
	unit := []byte(renderOpenConnectUnit(ch, confPath, passwordPath))
	changed := system.FileChanged(confPath, conf) || system.FileChanged(passwordPath, password) ||
		system.FileChanged(scriptPath, script) || system.FileChanged(unitPath, unit)
	for _, file := range []struct {
		path string
		data []byte
		perm os.FileMode
	}{{confPath, conf, 0o600}, {passwordPath, password, 0o600}, {scriptPath, script, 0o700}, {unitPath, unit, 0o644}} {
		if err := writeFileIfChanged(file.path, file.data, file.perm); err != nil {
			return false, err
		}
		mutated = true
	}
	unitName := openConnectUnitName(ch)
	if changed {
		if _, err := s.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return false, err
		}
	}
	if err := s.ensureUnitEnabled(ctx, unitName); err != nil {
		return false, err
	}
	active, _ := s.Runner.Run(ctx, "systemctl", "is-active", unitName)
	if changed || strings.TrimSpace(active) != "active" {
		if _, err := s.Runner.Run(ctx, "systemctl", "restart", unitName); err != nil {
			return false, fmt.Errorf("запуск OpenConnect: %w", err)
		}
	}
	deadline := time.Now().Add(20 * time.Second)
	for !s.linkExists(InterfaceName(ch)) && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	if !s.linkExists(InterfaceName(ch)) {
		return false, fmt.Errorf("OpenConnect не создал интерфейс %s", InterfaceName(ch))
	}
	created = !existedBefore
	if disableIPv6 {
		if err := s.suppressIPv6(InterfaceName(ch)); err != nil {
			return created, err
		}
	}
	if err := s.ensureRoutes(ctx, ch, InterfaceName(ch)); err != nil {
		return created, err
	}
	if err := s.ensureRule(ctx, ch); err != nil {
		return created, err
	}
	return created, nil
}

func (s *Subsystem) cleanupOpenConnect(ctx context.Context, ch config.Channel) {
	unitName := openConnectUnitName(ch)
	_, _ = s.Runner.Run(ctx, "systemctl", "disable", unitName)
	_, _ = s.Runner.Run(ctx, "systemctl", "stop", unitName)
	conf, password, script, unit := s.openConnectPaths(ch)
	for _, path := range []string{conf, password, script, unit} {
		_ = os.Remove(path)
	}
	_, _ = s.Runner.Run(ctx, "systemctl", "daemon-reload")
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
