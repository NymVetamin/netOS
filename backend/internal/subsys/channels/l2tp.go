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

func l2tpUnitName(ch config.Channel) string {
	return fmt.Sprintf("netos-vpn-l2tp-ch%d.service", ch.Index)
}

func (s *Subsystem) l2tpPaths(ch config.Channel) (conf, ppp, unit string) {
	base := filepath.Join(s.StateDir, fmt.Sprintf("vpn-l2tp-ch%d", ch.Index))
	return base + ".conf", base + ".ppp", filepath.Join(s.UnitDir, l2tpUnitName(ch))
}

func renderL2TPConf(ch config.Channel, l2tp config.L2TPChannelConfig, ppp string) string {
	return fmt.Sprintf("[global]\nport = %d\naccess control = no\n\n[lac netos-ch%d]\nlns = %s\nname = %s\npppoptfile = %s\nrequire authentication = no\nautodial = yes\nredial = yes\nredial timeout = 5\nmax redials = 2000000000\nlength bit = yes\n", 20000+ch.Index, ch.Index, l2tp.Server, l2tp.Username, ppp)
}

func renderL2TPPPP(ch config.Channel, l2tp config.L2TPChannelConfig) string {
	mtu := l2tp.MTU
	if mtu == 0 {
		mtu = 1400
	}
	return fmt.Sprintf("ifname %s\nuser %q\npassword %q\nhide-password\nnoauth\nnoipdefault\nnodefaultroute\nmtu %d\nmru %d\nnoipv6\nlcp-echo-interval 20\nlcp-echo-failure 3\n", InterfaceName(ch), l2tp.Username, l2tp.Password, mtu, mtu)
}

func renderL2TPUnit(ch config.Channel, conf string) string {
	return fmt.Sprintf(`[Unit]
Description=netOS: L2TP channel %s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/xl2tpd -D -c %s -p /run/netos-l2tp-ch%d.pid -C /run/netos-l2tp-ch%d.ctl
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, ch.Name, conf, ch.Index, ch.Index)
}

func (s *Subsystem) applyL2TP(ctx context.Context, ch config.Channel, wasOwned, disableIPv6 bool) (created bool, retErr error) {
	name := InterfaceName(ch)
	existedBefore := s.linkExists(name)
	if existedBefore && !wasOwned {
		return false, fmt.Errorf("интерфейс %s уже существует и не принадлежит netOS", name)
	}
	l2tp, err := ch.L2TPConfig()
	if err != nil {
		return false, err
	}
	confPath, pppPath, unitPath := s.l2tpPaths(ch)
	snapshots, err := captureChannelFiles(confPath, pppPath, unitPath)
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
			s.cleanupL2TP(rollbackCtx, ch)
			_, _ = s.Runner.Run(rollbackCtx, "ip", "-4", "rule", "del", "priority", fmt.Sprint(Priority(ch)))
			_, _ = s.Runner.Run(rollbackCtx, "ip", "-4", "route", "flush", "table", fmt.Sprint(TableNumber(ch)))
			return
		}
		if err := restoreChannelFiles(snapshots); err != nil {
			retErr = fmt.Errorf("%v; rollback L2TP: %w", retErr, err)
			return
		}
		_, _ = s.Runner.Run(rollbackCtx, "systemctl", "daemon-reload")
		_, _ = s.Runner.Run(rollbackCtx, "systemctl", "restart", l2tpUnitName(ch))
	}()
	conf := []byte(renderL2TPConf(ch, l2tp, pppPath))
	ppp := []byte(renderL2TPPPP(ch, l2tp))
	unit := []byte(renderL2TPUnit(ch, confPath))
	changed := system.FileChanged(confPath, conf) || system.FileChanged(pppPath, ppp) || system.FileChanged(unitPath, unit)
	for _, file := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{confPath, conf, 0o600}, {pppPath, ppp, 0o600}, {unitPath, unit, 0o644},
	} {
		if err := writeFileIfChanged(file.path, file.data, file.mode); err != nil {
			return false, err
		}
		mutated = true
	}
	if changed {
		if _, err := s.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return false, err
		}
	}
	unitName := l2tpUnitName(ch)
	if err := s.ensureUnitEnabled(ctx, unitName); err != nil {
		return false, err
	}
	active, _ := s.Runner.Run(ctx, "systemctl", "is-active", unitName)
	if changed || strings.TrimSpace(active) != "active" {
		if _, err := s.Runner.Run(ctx, "systemctl", "restart", unitName); err != nil {
			return false, fmt.Errorf("запуск L2TP: %w", err)
		}
	}
	deadline := time.Now().Add(45 * time.Second)
	for !s.openConnectReady(ctx, name) {
		if !time.Now().Before(deadline) {
			return false, fmt.Errorf("L2TP не подготовил интерфейс %s (UP и IPv4-адрес)", name)
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	created = !existedBefore
	if disableIPv6 {
		if err := s.suppressIPv6(name); err != nil {
			return created, err
		}
	}
	if err := s.ensureRoutes(ctx, ch, name); err != nil {
		return created, err
	}
	if err := s.ensureRule(ctx, ch); err != nil {
		return created, err
	}
	return created, nil
}

func (s *Subsystem) cleanupL2TP(ctx context.Context, ch config.Channel) {
	unitName := l2tpUnitName(ch)
	_, _ = s.Runner.Run(ctx, "systemctl", "disable", unitName)
	_, _ = s.Runner.Run(ctx, "systemctl", "stop", unitName)
	conf, ppp, unit := s.l2tpPaths(ch)
	for _, path := range []string{conf, ppp, unit} {
		_ = os.Remove(path)
	}
	_, _ = s.Runner.Run(ctx, "systemctl", "daemon-reload")
}
