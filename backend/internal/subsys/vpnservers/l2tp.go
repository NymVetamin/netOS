package vpnservers

import (
	"context"
	"fmt"
	"net/netip"
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
func l2tpPPPName(server config.VPNServer) string { return config.L2TPInterfacePrefix(server.Index) }
func l2tpAuthName(server config.VPNServer) string {
	return fmt.Sprintf("netos-l2tp-srv%d", server.Index)
}

func (s *Subsystem) l2tpPaths(server config.VPNServer) (conf, ppp, unit string) {
	base := filepath.Join(s.StateDir, fmt.Sprintf("vpn-l2tp-srv%d", server.Index))
	return base + ".conf", base + ".ppp", filepath.Join(s.UnitDir, l2tpUnitName(server))
}

func renderL2TPConf(server config.VPNServer, l2tp config.L2TPServerConfig, ppp string) string {
	localIP := strings.Split(server.Subnet, "/")[0]
	return fmt.Sprintf("[global]\nport = 1701\nlisten-addr = %s\naccess control = no\n\n[lns default]\nassign ip = no\nlocal ip = %s\nrequire chap = yes\nrefuse pap = yes\nrequire authentication = yes\nname = %s\npppoptfile = %s\nlength bit = yes\n", l2tp.Listen, localIP, l2tpAuthName(server), ppp)
}

func renderL2TPPPP(server config.VPNServer, l2tp config.L2TPServerConfig) string {
	mtu := l2tp.MTU
	if mtu == 0 {
		mtu = 1400
	}
	auth := "require-chap"
	if l2tp.IPsec {
		auth = "require-mschap-v2"
	}
	text := fmt.Sprintf("name %s\nauth\n%s\nrefuse-pap\nnodefaultroute\nmtu %d\nmru %d\nnoipv6\nlcp-echo-interval 20\nlcp-echo-failure 3\n", l2tpAuthName(server), auth, mtu, mtu)
	for _, address := range l2tp.DNS {
		text += "ms-dns " + address + "\n"
	}
	return text
}

func (s *Subsystem) l2tpPreUpPath(server config.VPNServer) string {
	return filepath.Join(s.StateDir, fmt.Sprintf("vpn-l2tp-srv%d.pre-up", server.Index))
}

// pppd re-reads the interface name after synchronous ip-pre-up. Bind it to
// the authenticated peer before enabling traffic, then optionally wait for
// Samba's listener. Deleting a rejected new interface makes IPCP fail closed;
// an already connected peer using the same address is left untouched.
func renderL2TPPreUp(server config.VPNServer, cfg *config.Config) []byte {
	prefix, err := netip.ParsePrefix(server.Subnet)
	if !server.Enabled || err != nil || !prefix.Addr().Is4() {
		return []byte("#!/bin/sh\nexit 0\n")
	}
	var out strings.Builder
	fmt.Fprintf(&out, "#!/bin/sh\n[ \"$4\" = %q ] || exit 0\ncase \"$1\" in ppp[0-9]*) ;; *) exit 0 ;; esac\nname=''\ncase \"$PEERNAME/$5\" in\n", prefix.Addr().String())
	for _, peer := range server.Peers {
		if peer.Enabled {
			identity := "'" + strings.ReplaceAll(peer.Credentials["username"]+"/"+peer.Address, "'", "'\"'\"'") + "'"
			fmt.Fprintf(&out, "    %s) name=%s ;;\n", identity, config.L2TPPeerInterface(server.Index, peer.Address))
		}
	}
	out.WriteString("esac\nif [ -z \"$name\" ] || ! ip link set dev \"$1\" name \"$name\"; then\n    ip link delete dev \"$1\"\n    exit 1\nfi\n")
	selected := false
	for _, id := range cfg.Samba.VPNs {
		selected = selected || id == server.ID
	}
	if !cfg.Samba.Enabled || !selected {
		out.WriteString("exit 0\n")
		return []byte(out.String())
	}
	fmt.Fprintf(&out, `systemctl is-active --quiet netos-samba.service || exit 0
timeout 10 /bin/sh -c '
while :; do
    ss -H -lnt | awk '\''$4 == "%s:445" { found=1 } END { exit !found }'\'' && exit 0
    sleep 0.1
done
'
exit 0
`, prefix.Addr().String())
	return []byte(out.String())
}

func renderL2TPUnit(server config.VPNServer, conf string) string {
	preStart := ""
	if server.UsesL2TPIPsec() {
		preStart = "ExecStartPre=/bin/sh " + conf + ".ipsec-guard\n"
	}
	return fmt.Sprintf(`[Unit]
Description=netOS: L2TP server %s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
%sExecStart=/usr/sbin/xl2tpd -D -c %s -p /run/netos-l2tp-srv%d.pid -C /run/netos-l2tp-srv%d.ctl
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, server.Name, preStart, conf, server.Index, server.Index)
}

func l2tpChapBlock(server config.VPNServer) string {
	name := l2tpAuthName(server)
	var out strings.Builder
	fmt.Fprintf(&out, "# BEGIN %s\n", name)
	for _, peer := range server.Peers {
		if peer.Enabled {
			fmt.Fprintf(&out, "%q %q %q %s\n", peer.Credentials["username"], name, peer.Credentials["password"], peer.Address)
		}
	}
	fmt.Fprintf(&out, "# END %s\n", name)
	return out.String()
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

func (s *Subsystem) applyL2TP(ctx context.Context, server config.VPNServer, cfg *config.Config, wasOwned bool) (created bool, retErr error) {
	confPath, pppPath, unitPath := s.l2tpPaths(server)
	preUpPath := s.l2tpPreUpPath(server)
	preUpLink := s.l2tpPreUpLink(server)
	if err := checkPreUpLink(preUpLink, preUpPath); err != nil {
		return false, err
	}
	if _, err := os.Stat(unitPath); err == nil && !wasOwned {
		return false, fmt.Errorf("служба %s существует и не принадлежит netOS", l2tpUnitName(server))
	}
	snapshots, err := capturePaths(confPath, confPath+".ipsec-guard", pppPath, unitPath, preUpPath, preUpLink, l2tpChapSecrets)
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
	if l2tp.IPsec {
		if err := writeFile(confPath+".ipsec-guard", renderL2TPIPsecGuard(server), 0o700); err != nil {
			return false, err
		}
		mutated = true
	} else if err := os.Remove(confPath + ".ipsec-guard"); err != nil && !os.IsNotExist(err) {
		return false, err
	} else if err == nil {
		mutated = true
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
	restart := system.FileChanged(confPath, conf) || system.FileChanged(pppPath, ppp) || system.UnitRuntimeChanged(unitPath, unit) || system.FileChanged(l2tpChapSecrets, newChap)
	for _, file := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		// Hook content follows Samba selection without restarting PPP sessions.
		{preUpPath, renderL2TPPreUp(server, cfg), 0o700},
		{confPath, conf, 0o600}, {pppPath, ppp, 0o600}, {unitPath, unit, 0o644}, {l2tpChapSecrets, newChap, 0o600},
	} {
		if err := writeFile(file.path, file.data, file.mode); err != nil {
			return false, err
		}
		mutated = true
	}
	if _, err := os.Lstat(preUpLink); os.IsNotExist(err) {
		if err := os.MkdirAll(s.PreUpDir, 0o755); err != nil {
			return false, err
		}
		if err := os.Symlink(preUpPath, preUpLink); err != nil {
			return false, err
		}
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
	if restart || strings.TrimSpace(active) != "active" {
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
	_ = removePreUpLink(s.l2tpPreUpLink(server), s.l2tpPreUpPath(server))
	conf, ppp, unitPath := s.l2tpPaths(server)
	for _, path := range []string{conf, conf + ".ipsec-guard", ppp, unitPath, s.l2tpPreUpPath(server)} {
		_ = os.Remove(path)
	}
	if chap, err := os.ReadFile(l2tpChapSecrets); err == nil {
		if next, err := updateL2TPChap(chap, server, false); err == nil {
			_ = writeFile(l2tpChapSecrets, next, 0o600)
		}
	}
	_, _ = s.Runner.Run(ctx, "systemctl", "daemon-reload")
	// xl2tpd may exit with status 1 on a normal SIGTERM. Once its unit has
	// been removed, clear only that unit's failed state from systemd.
	_, _ = s.Runner.Run(ctx, "systemctl", "reset-failed", unit)
}
