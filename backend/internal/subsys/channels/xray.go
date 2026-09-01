package channels

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func xrayUnitName(ch config.Channel) string {
	return fmt.Sprintf("netos-xray-ch%d.service", ch.Index)
}

func xrayGateway(ch config.Channel) string {
	// One non-overlapping /30 per channel from the RFC 2544 benchmarking
	// range. Channel indexes are capped at 9999, so they fit in 198.18/16.
	offset := ch.Index*4 + 1
	return fmt.Sprintf("198.18.%d.%d/30", offset/256, offset%256)
}

func (s *Subsystem) xrayPaths(ch config.Channel) (conf, unit string) {
	return filepath.Join(s.StateDir, fmt.Sprintf("xray-ch%d.json", ch.Index)),
		filepath.Join(s.UnitDir, xrayUnitName(ch))
}

func RenderXray(ch config.Channel) ([]byte, error) {
	xr, err := ch.XrayConfig()
	if err != nil {
		return nil, err
	}
	// Clone the user-provided outbound before assigning the internal tag. The
	// original config remains byte-for-byte suitable for revisions and UI edits.
	encoded, err := json.Marshal(xr.Outbound)
	if err != nil {
		return nil, fmt.Errorf("кодирование outbound Xray: %w", err)
	}
	var outbound map[string]any
	if err := json.Unmarshal(encoded, &outbound); err != nil {
		return nil, err
	}
	outbound["tag"] = "proxy"
	mtu := xr.MTU
	if mtu == 0 {
		mtu = 1400
	}
	document := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag": "netos-tun", "protocol": "tun",
			"settings": map[string]any{
				"name": InterfaceName(ch), "mtu": mtu,
				"gateway": []string{xrayGateway(ch)},
			},
			"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true},
		}},
		"outbounds": []any{outbound},
		"routing": map[string]any{
			"domainStrategy": "IPIfNonMatch",
			"rules":          []any{map[string]any{"type": "field", "inboundTag": []string{"netos-tun"}, "outboundTag": "proxy"}},
		},
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func renderXrayUnit(ch config.Channel, conf string) string {
	return `[Unit]
Description=netOS: Xray-канал ` + ch.Name + `
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/usr/local/bin/xray run -test -config ` + conf + `
ExecStart=/usr/local/bin/xray run -config ` + conf + `
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
`
}

func (s *Subsystem) applyXray(ctx context.Context, ch config.Channel, wasOwned, disableIPv6 bool) (created bool, retErr error) {
	existedBefore := s.linkExists(InterfaceName(ch))
	if existedBefore && !wasOwned {
		return false, fmt.Errorf("интерфейс %s уже существует и не принадлежит netOS", InterfaceName(ch))
	}
	conf, err := RenderXray(ch)
	if err != nil {
		return false, err
	}
	confPath, unitPath := s.xrayPaths(ch)
	snapshots, err := captureChannelFiles(confPath, unitPath)
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
			s.cleanupXray(rollbackCtx, ch)
			_, _ = s.Runner.Run(rollbackCtx, "ip", "-4", "rule", "del", "priority", fmt.Sprint(Priority(ch)))
			_, _ = s.Runner.Run(rollbackCtx, "ip", "-4", "route", "flush", "table", fmt.Sprint(TableNumber(ch)))
			if s.linkExists(InterfaceName(ch)) {
				_, _ = s.Runner.Run(rollbackCtx, "ip", "link", "delete", InterfaceName(ch))
			}
			return
		}
		if err := restoreChannelFiles(snapshots); err != nil {
			retErr = fmt.Errorf("%v; rollback Xray: %w", retErr, err)
			return
		}
		_, _ = s.Runner.Run(rollbackCtx, "systemctl", "daemon-reload")
		_, _ = s.Runner.Run(rollbackCtx, "systemctl", "restart", xrayUnitName(ch))
	}()
	// Xray detects the config format by the final filename extension.
	candidate := strings.TrimSuffix(confPath, filepath.Ext(confPath)) + ".candidate.json"
	if err := writeFileIfChanged(candidate, conf, 0o600); err != nil {
		return false, err
	}
	defer os.Remove(candidate)
	if _, err := s.Runner.Run(ctx, "/usr/local/bin/xray", "run", "-test", "-config", candidate); err != nil {
		return false, fmt.Errorf("проверка конфигурации Xray: %w", err)
	}
	unit := []byte(renderXrayUnit(ch, confPath))
	changed := system.FileChanged(confPath, conf) || system.FileChanged(unitPath, unit)
	if err := os.Rename(candidate, confPath); err != nil {
		return false, err
	}
	mutated = true
	if err := os.Chmod(confPath, 0o600); err != nil {
		return false, err
	}
	if err := writeFileIfChanged(unitPath, unit, 0o644); err != nil {
		return false, err
	}
	unitName := xrayUnitName(ch)
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
			return false, fmt.Errorf("запуск Xray: %w", err)
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
		return false, fmt.Errorf("Xray не создал интерфейс %s", InterfaceName(ch))
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

func (s *Subsystem) cleanupXray(ctx context.Context, ch config.Channel) {
	unitName := xrayUnitName(ch)
	_, _ = s.Runner.Run(ctx, "systemctl", "disable", unitName)
	_, _ = s.Runner.Run(ctx, "systemctl", "stop", unitName)
	conf, unit := s.xrayPaths(ch)
	candidate := strings.TrimSuffix(conf, filepath.Ext(conf)) + ".candidate.json"
	for _, path := range []string{conf, candidate, unit} {
		_ = os.Remove(path)
	}
	_, _ = s.Runner.Run(ctx, "systemctl", "daemon-reload")
}
