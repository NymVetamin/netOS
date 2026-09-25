package vpnservers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

const l2tpChapSecrets = "/etc/ppp/chap-secrets"

func l2tpUnitName(server config.VPNServer) string {
	return fmt.Sprintf("netos-vpn-l2tp-srv%d.service", server.Index)
}
func l2tpPPPName(server config.VPNServer) string { return fmt.Sprintf("ppp-srv%d", server.Index) }
func l2tpAuthName(server config.VPNServer) string {
	return fmt.Sprintf("netos-l2tp-srv%d", server.Index)
}

func (s *Subsystem) l2tpPaths(server config.VPNServer) (conf, ppp, unit string) {
	base := filepath.Join(s.StateDir, fmt.Sprintf("vpn-l2tp-srv%d", server.Index))
	return base + ".conf", base + ".ppp", filepath.Join(s.UnitDir, l2tpUnitName(server))
}

func l2tpPeer(server config.VPNServer) config.VPNPeer {
	for _, peer := range server.Peers {
		if peer.Enabled {
			return peer
		}
	}
	return config.VPNPeer{}
}

func renderL2TPConf(server config.VPNServer, l2tp config.L2TPServerConfig, ppp string) string {
	peer := l2tpPeer(server)
	localIP := strings.Split(server.Subnet, "/")[0]
	return fmt.Sprintf("[global]\nport = 1701\nlisten-addr = %s\naccess control = no\n\n[lns default]\nip range = %s-%s\nlocal ip = %s\nrequire chap = yes\nrefuse pap = yes\nrequire authentication = yes\nname = %s\npppoptfile = %s\nlength bit = yes\n", l2tp.Listen, peer.Address, peer.Address, localIP, l2tpAuthName(server), ppp)
}

func renderL2TPPPP(server config.VPNServer, l2tp config.L2TPServerConfig) string {
	mtu := l2tp.MTU
	if mtu == 0 {
		mtu = 1400
	}
	return fmt.Sprintf("ifname %s\nname %s\nauth\nrequire-chap\nrefuse-pap\nnodefaultroute\nmtu %d\nmru %d\nnoipv6\nlcp-echo-interval 20\nlcp-echo-failure 3\n", l2tpPPPName(server), l2tpAuthName(server), mtu, mtu)
}

func renderL2TPUnit(server config.VPNServer, conf string) string {
	return fmt.Sprintf(`[Unit]
Description=netOS: L2TP server %s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/xl2tpd -D -c %s -p /run/netos-l2tp-srv%d.pid -C /run/netos-l2tp-srv%d.ctl
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, server.Name, conf, server.Index, server.Index)
}

func l2tpChapBlock(server config.VPNServer) string {
	peer := l2tpPeer(server)
	name := l2tpAuthName(server)
	return fmt.Sprintf("# BEGIN %s\n%q %q %q %s\n# END %s\n", name, peer.Credentials["username"], name, peer.Credentials["password"], peer.Address, name)
}

func updateL2TPChap(data []byte, server config.VPNServer, add bool) ([]byte, error) {
	name := l2tpAuthName(server)
	begin := "# BEGIN " + name + "\n"
	end := "# END " + name + "\n"
	text := string(data)
	if start := strings.Index(text, begin); start >= 0 {
		finish := strings.Index(text[start:], end)
		if finish < 0 {
			return nil, fmt.Errorf("повреждён управляемый блок %s в chap-secrets", name)
		}
		text = text[:start] + text[start+finish+len(end):]
	}
	if add {
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		text += l2tpChapBlock(server)
	}
	return []byte(text), nil
}

func (s *Subsystem) applyL2TP(ctx context.Context, server config.VPNServer, wasOwned bool) (created bool, retErr error) {
	confPath, pppPath, unitPath := s.l2tpPaths(server)
	if _, err := os.Stat(unitPath); err == nil && !wasOwned {
		return false, fmt.Errorf("служба %s существует и не принадлежит netOS", l2tpUnitName(server))
	}
	snapshots, err := capturePaths(confPath, pppPath, unitPath, l2tpChapSecrets)
	if err != nil {
		return false, err
	}
	mutated := false
	defer func() {
		if retErr == nil || !mutated {
			return
		}
		rollbackCtx := context.Background()
		if err := restorePaths(snapshots); err != nil {
			retErr = fmt.Errorf("%v; rollback L2TP: %w", retErr, err)
			return
		}
		_, _ = s.Runner.Run(rollbackCtx, "systemctl", "daemon-reload")
		if wasOwned {
			_, _ = s.Runner.Run(rollbackCtx, "systemctl", "restart", l2tpUnitName(server))
		} else {
			_, _ = s.Runner.Run(rollbackCtx, "systemctl", "disable", l2tpUnitName(server))
			_, _ = s.Runner.Run(rollbackCtx, "systemctl", "stop", l2tpUnitName(server))
		}
	}()
	l2tp, err := server.L2TPConfig()
	if err != nil {
		return false, err
	}
	chap, err := os.ReadFile(l2tpChapSecrets)
	if os.IsNotExist(err) {
		chap = nil
	} else if err != nil {
		return false, err
	}
	newChap, err := updateL2TPChap(chap, server, true)
	if err != nil {
		return false, err
	}
	conf := []byte(renderL2TPConf(server, l2tp, pppPath))
	ppp := []byte(renderL2TPPPP(server, l2tp))
	unit := []byte(renderL2TPUnit(server, confPath))
	changed := system.FileChanged(confPath, conf) || system.FileChanged(pppPath, ppp) || system.FileChanged(unitPath, unit) || system.FileChanged(l2tpChapSecrets, newChap)
	for _, file := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{confPath, conf, 0o600}, {pppPath, ppp, 0o600}, {unitPath, unit, 0o644}, {l2tpChapSecrets, newChap, 0o600},
	} {
		if err := writeFile(file.path, file.data, file.mode); err != nil {
			return false, err
		}
		mutated = true
	}
	if changed {
		if _, err := s.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return false, err
		}
	}
	unitName := l2tpUnitName(server)
	if err := s.ensureUnitEnabled(ctx, unitName); err != nil {
		return false, err
	}
	active, _ := s.Runner.Run(ctx, "systemctl", "is-active", unitName)
	if changed || strings.TrimSpace(active) != "active" {
		if _, err := s.Runner.Run(ctx, "systemctl", "restart", unitName); err != nil {
			return false, fmt.Errorf("запуск L2TP-сервера: %w", err)
		}
	}
	return !wasOwned, nil
}

func (s *Subsystem) cleanupL2TP(ctx context.Context, server config.VPNServer) {
	unit := l2tpUnitName(server)
	_, _ = s.Runner.Run(ctx, "systemctl", "disable", unit)
	_, _ = s.Runner.Run(ctx, "systemctl", "stop", unit)
	conf, ppp, unitPath := s.l2tpPaths(server)
	for _, path := range []string{conf, ppp, unitPath} {
		_ = os.Remove(path)
	}
	if chap, err := os.ReadFile(l2tpChapSecrets); err == nil {
		if next, err := updateL2TPChap(chap, server, false); err == nil {
			_ = writeFile(l2tpChapSecrets, next, 0o600)
		}
	}
	_, _ = s.Runner.Run(ctx, "systemctl", "daemon-reload")
}
