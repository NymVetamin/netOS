package vpnservers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
	"github.com/netos-router/netos/internal/tlsutil"
)

type ocservPaths struct {
	conf, passwd, users, tls, auth, unit string
}

func ocservUnitName(server config.VPNServer) string {
	return fmt.Sprintf("netos-ocserv-srv%d.service", server.Index)
}

func (s *Subsystem) ocservPaths(server config.VPNServer) ocservPaths {
	prefix := filepath.Join(s.StateDir, fmt.Sprintf("ocserv-srv%d", server.Index))
	return ocservPaths{
		conf: prefix + ".conf", passwd: prefix + ".passwd", users: prefix + "-users", tls: prefix + "-tls",
		auth: prefix + ".auth.sha256",
		unit: filepath.Join(s.UnitDir, ocservUnitName(server)),
	}
}

func RenderOcserv(server config.VPNServer, cfg *config.Config, stateDir string) ([]byte, error) {
	oc, err := server.OcservConfig()
	if err != nil {
		return nil, err
	}
	prefix := path.Join(stateDir, fmt.Sprintf("ocserv-srv%d", server.Index))
	parsed, err := netip.ParsePrefix(server.Subnet)
	if err != nil {
		return nil, err
	}
	network := parsed.Masked()
	mtu := oc.MTU
	if mtu == 0 {
		mtu = 1380
	}
	var b strings.Builder
	fmt.Fprintln(&b, "# Сгенерировано netOS. Файл содержит пути к секретам; права 0600.")
	fmt.Fprintf(&b, "auth = \"plain[passwd=%s.passwd]\"\n", prefix)
	fmt.Fprintln(&b, "listen-host = 0.0.0.0")
	fmt.Fprintf(&b, "tcp-port = %d\nudp-port = %d\n", server.Port, server.Port)
	fmt.Fprintln(&b, "run-as-user = ocserv\nrun-as-group = ocserv")
	fmt.Fprintf(&b, "socket-file = /run/netos-ocserv-srv%d/socket\n", server.Index)
	fmt.Fprintf(&b, "occtl-socket-file = /run/netos-ocserv-srv%d/occtl.socket\n", server.Index)
	fmt.Fprintf(&b, "pid-file = /run/netos-ocserv-srv%d/ocserv.pid\n", server.Index)
	fmt.Fprintf(&b, "server-cert = %s-tls/panel.crt\nserver-key = %s-tls/panel.key\n", prefix, prefix)
	fmt.Fprintf(&b, "device = vpns%d\n", server.Index)
	fmt.Fprintln(&b, "isolate-workers = true\nmax-clients = 128\nmax-same-clients = 2")
	fmt.Fprintln(&b, "keepalive = 30\ndpd = 60\nmobile-dpd = 300\nauth-timeout = 60\ncookie-timeout = 3600")
	fmt.Fprintln(&b, "predictable-ips = true\nping-leases = false\ncisco-client-compat = true")
	fmt.Fprintf(&b, "ipv4-network = %s\n", network)
	fmt.Fprintf(&b, "config-per-user = %s-users\n", prefix)
	fmt.Fprintf(&b, "mtu = %d\n", mtu)
	if len(oc.Routes) == 0 {
		fmt.Fprintln(&b, "route = default\ntunnel-all-dns = true")
	} else {
		for _, route := range oc.Routes {
			fmt.Fprintf(&b, "route = %s\n", route)
		}
	}
	for _, dns := range oc.DNS {
		fmt.Fprintf(&b, "dns = %s\n", dns)
	}
	if oc.Banner != "" {
		fmt.Fprintf(&b, "banner = %q\n", oc.Banner)
	}
	return []byte(b.String()), nil
}

func renderOcservUnit(server config.VPNServer, conf string) string {
	return `[Unit]
Description=netOS: OpenConnect server ` + server.Name + `
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
RuntimeDirectory=netos-ocserv-srv` + fmt.Sprint(server.Index) + `
RuntimeDirectoryMode=0755
ExecStart=/usr/sbin/ocserv --foreground --config ` + conf + `
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
CapabilityBoundingSet=CAP_CHOWN CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETGID CAP_SETUID
AmbientCapabilities=CAP_CHOWN CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETGID CAP_SETUID

[Install]
WantedBy=multi-user.target
`
}

func (s *Subsystem) applyOcserv(ctx context.Context, cfg *config.Config, server config.VPNServer) (bool, error) {
	paths := s.ocservPaths(server)
	_, statErr := os.Stat(paths.unit)
	existed := statErr == nil
	certPath := filepath.Join(paths.tls, "panel.crt")
	certBefore, _ := os.ReadFile(certPath)
	if _, _, _, err := tlsutil.EnsureSelfSigned(paths.tls, cfg.System.Hostname); err != nil {
		return false, fmt.Errorf("сертификат: %w", err)
	}
	certAfter, _ := os.ReadFile(certPath)
	certChanged := string(certBefore) != string(certAfter)
	conf, err := RenderOcserv(server, cfg, s.StateDir)
	if err != nil {
		return false, err
	}
	confCandidate := paths.conf + ".candidate"
	passwdCandidate := paths.passwd + ".candidate"
	usersCandidate := paths.users + ".candidate"
	defer os.Remove(confCandidate)
	defer os.Remove(passwdCandidate)
	defer os.RemoveAll(usersCandidate)
	authJSON, err := json.Marshal(server.Peers)
	if err != nil {
		return false, err
	}
	authSum := sha256.Sum256(authJSON)
	authData := []byte(hex.EncodeToString(authSum[:]) + "\n")
	authChanged := system.FileChanged(paths.auth, authData)
	if _, err := os.Stat(paths.passwd); err != nil {
		authChanged = true
	}
	if _, err := os.Stat(paths.users); err != nil {
		authChanged = true
	}
	testConf := conf
	if authChanged {
		testConf = []byte(strings.ReplaceAll(strings.ReplaceAll(string(conf), paths.passwd, passwdCandidate), paths.users, usersCandidate))
	}
	if err := system.WriteFileAtomic(confCandidate, testConf, 0o600); err != nil {
		return false, err
	}
	if authChanged {
		if err := system.WriteFileAtomic(passwdCandidate, nil, 0o600); err != nil {
			return false, err
		}
		if err := os.MkdirAll(usersCandidate, 0o700); err != nil {
			return false, err
		}
		for _, peer := range server.Peers {
			if !peer.Enabled {
				continue
			}
			username, password := peer.Credentials["username"], peer.Credentials["password"]
			if _, err := s.Runner.RunInput(ctx, password+"\n"+password+"\n", "ocpasswd", "-c", passwdCandidate, username); err != nil {
				return false, fmt.Errorf("пароль пользователя %s: %w", username, err)
			}
			userConfig := []byte("explicit-ipv4 = " + peer.Address + "\n")
			if err := system.WriteFileAtomic(filepath.Join(usersCandidate, username), userConfig, 0o600); err != nil {
				return false, err
			}
		}
	}
	if _, err := s.Runner.Run(ctx, "/usr/sbin/ocserv", "--test-config", "--config", confCandidate); err != nil {
		return false, fmt.Errorf("проверка конфигурации ocserv: %w", err)
	}
	unit := []byte(renderOcservUnit(server, paths.conf))
	changed := system.FileChanged(paths.conf, conf) || authChanged || certChanged || system.FileChanged(paths.unit, unit)
	if authChanged {
		if err := replaceDir(usersCandidate, paths.users); err != nil {
			return false, err
		}
		if err := os.Rename(passwdCandidate, paths.passwd); err != nil {
			return false, err
		}
		if err := os.Chmod(paths.passwd, 0o600); err != nil {
			return false, err
		}
		if err := system.WriteFileAtomic(paths.auth, authData, 0o600); err != nil {
			return false, err
		}
	}
	if err := system.WriteFileAtomic(confCandidate, conf, 0o600); err != nil {
		return false, err
	}
	if err := os.Rename(confCandidate, paths.conf); err != nil {
		return false, err
	}
	if err := os.Chmod(paths.conf, 0o600); err != nil {
		return false, err
	}
	if err := system.WriteFileAtomic(paths.unit, unit, 0o644); err != nil {
		return false, err
	}
	if changed {
		if _, err := s.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return false, err
		}
	}
	name := ocservUnitName(server)
	if _, err := s.Runner.Run(ctx, "systemctl", "enable", name); err != nil {
		return false, err
	}
	active, _ := s.Runner.Run(ctx, "systemctl", "is-active", name)
	if changed || strings.TrimSpace(active) != "active" {
		if _, err := s.Runner.Run(ctx, "systemctl", "restart", name); err != nil {
			s.cleanupOcserv(ctx, server)
			return false, fmt.Errorf("запуск ocserv: %w", err)
		}
	}
	return !existed, nil
}

func replaceDir(candidate, target string) error {
	backup := target + ".old"
	_ = os.RemoveAll(backup)
	if err := os.Rename(target, backup); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(candidate, target); err != nil {
		_ = os.Rename(backup, target)
		return err
	}
	return os.RemoveAll(backup)
}

func (s *Subsystem) cleanupOcserv(ctx context.Context, server config.VPNServer) {
	name := ocservUnitName(server)
	_, _ = s.Runner.Run(ctx, "systemctl", "disable", name)
	_, _ = s.Runner.Run(ctx, "systemctl", "stop", name)
	paths := s.ocservPaths(server)
	for _, path := range []string{paths.conf, paths.conf + ".candidate", paths.passwd, paths.passwd + ".candidate", paths.auth, paths.unit} {
		_ = os.Remove(path)
	}
	for _, path := range []string{paths.users, paths.users + ".candidate", paths.users + ".old", paths.tls} {
		_ = os.RemoveAll(path)
	}
	_, _ = s.Runner.Run(ctx, "systemctl", "daemon-reload")
}
