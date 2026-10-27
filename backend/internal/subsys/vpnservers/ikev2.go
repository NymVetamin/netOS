package vpnservers

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
	"github.com/netos-router/netos/internal/tlsutil"
)

const ikev2Unit = "netos-strongswan.service"

type ikev2Paths struct {
	root, conf, candidate, daemonConf, cert, key, sourceTLS, unit string
	authRoot, authUnit                                            string
}

func (s *Subsystem) ikev2Paths() ikev2Paths {
	root := filepath.Join(s.StateDir, "strongswan")
	return ikev2Paths{
		root: root, conf: filepath.Join(root, "swanctl.conf"), candidate: filepath.Join(root, "swanctl.conf.candidate"),
		daemonConf: filepath.Join(root, "strongswan.conf"),
		cert:       filepath.Join(root, "x509", "server.crt"), key: filepath.Join(root, "private", "server.key"),
		sourceTLS: filepath.Join(root, "tls"), unit: filepath.Join(s.UnitDir, ikev2Unit),
		authRoot: filepath.Join(root, "auth"), authUnit: filepath.Join(s.UnitDir, ikev2AuthUnit),
	}
}

func ikev2Servers(cfg *config.Config) []config.VPNServer {
	var out []config.VPNServer
	for _, server := range cfg.VPNServers {
		if server.Enabled && server.Type == "ikev2" {
			out = append(out, server)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

func ikev2Identity(server config.VPNServer, cfg *config.Config) string {
	ike, _ := server.IKEv2Config()
	if ike.ServerIdentity != "" {
		return ike.ServerIdentity
	}
	if ike.PublicEndpoint != "" {
		return ike.PublicEndpoint
	}
	return cfg.System.Hostname
}

func ikev2RoutesWithDNS(routes, dns []string) []string {
	out := append([]string(nil), routes...)
	for _, value := range dns {
		address, err := netip.ParseAddr(value)
		if err != nil {
			continue
		}
		included := false
		for _, route := range routes {
			prefix, err := netip.ParsePrefix(route)
			if err == nil && prefix.Contains(address) {
				included = true
				break
			}
		}
		if !included {
			out = append(out, netip.PrefixFrom(address, address.BitLen()).String())
		}
	}
	return out
}

// RenderIKEv2 binds each server to its XFRM interface and RADIUS group.
// RADIUS assigns the address from the authenticated account, not the IKE ID.
func RenderIKEv2(servers []config.VPNServer, cfg *config.Config) ([]byte, error) {
	return renderIPsecServers(servers, cfg, nil)
}

func renderIPsecServers(servers []config.VPNServer, cfg *config.Config, l2tp []config.VPNServer) ([]byte, error) {
	var b strings.Builder
	fmt.Fprintln(&b, "# Сгенерировано netOS. Авторизация и закреплённые адреса: локальный RADIUS.")
	fmt.Fprintln(&b, "connections {")
	for _, server := range servers {
		ike, err := server.IKEv2Config()
		if err != nil {
			return nil, err
		}
		identity := ikev2Identity(server, cfg)
		ts := ike.SplitRoutes
		if len(ts) == 0 {
			ts = []string{"0.0.0.0/0"}
		} else {
			ts = ikev2RoutesWithDNS(ts, ike.DNS)
		}
		fmt.Fprintf(&b, "  netos-srv%d {\n", server.Index)
		fmt.Fprintln(&b, "    version = 2")
		fmt.Fprintln(&b, "    local_addrs = 0.0.0.0")
		fmt.Fprintln(&b, "    pools = radius")
		fmt.Fprintln(&b, "    unique = replace")
		fmt.Fprintln(&b, "    proposals = aes256gcm16-prfsha384-ecp384,aes256-sha256-modp2048")
		fmt.Fprintln(&b, "    fragmentation = yes")
		fmt.Fprintln(&b, "    mobike = yes")
		fmt.Fprintln(&b, "    local {")
		fmt.Fprintln(&b, "      auth = pubkey")
		fmt.Fprintln(&b, "      certs = server.crt")
		fmt.Fprintf(&b, "      id = %s\n", identity)
		fmt.Fprintln(&b, "    }")
		fmt.Fprintln(&b, "    remote {")
		fmt.Fprintln(&b, "      auth = eap-radius")
		fmt.Fprintln(&b, "      eap_id = %any")
		fmt.Fprintf(&b, "      groups = netos-srv%d\n", server.Index)
		fmt.Fprintln(&b, "    }")
		fmt.Fprintln(&b, "    children {")
		fmt.Fprintf(&b, "      netos-srv%d {\n", server.Index)
		fmt.Fprintf(&b, "        local_ts = %s\n", strings.Join(ts, ", "))
		// Deliver decrypted traffic through the VPN interface as well. Services
		// such as dnsmasq use the arrival interface to admit VPN clients.
		fmt.Fprintf(&b, "        if_id_in = %d\n", 50000+server.Index)
		fmt.Fprintf(&b, "        if_id_out = %d\n", 50000+server.Index)
		fmt.Fprintln(&b, "        esp_proposals = aes256gcm16-ecp384,aes256-sha256-modp2048")
		fmt.Fprintln(&b, "        dpd_action = clear")
		fmt.Fprintln(&b, "        close_action = clear")
		fmt.Fprintln(&b, "      }")
		fmt.Fprintln(&b, "    }")
		fmt.Fprintln(&b, "  }")
	}
	for _, server := range l2tp {
		renderL2TPIPsecConnection(&b, server)
	}
	fmt.Fprintln(&b, "}")
	renderL2TPIPsecSecrets(&b, l2tp)
	return []byte(b.String()), nil
}

func renderIKEv2DaemonConfig(secret string) []byte {
	radius := ""
	if secret != "" {
		radius = `    eap-radius {
      load = yes
      class_group = yes
      servers {
        netos {
          address = 127.0.0.1
          port = ` + fmt.Sprint(config.IKEv2AuthPort) + `
          secret = ` + secret + `
          sockets = 4
        }
      }
    }
`
	}
	return []byte(`charon {
 load_modular = yes
 plugins {
 include /etc/strongswan.d/charon/*.conf
 vici {
  socket = unix:///run/netos-strongswan/charon.vici
 }
` + radius + ` }
}
include /etc/strongswan.d/*.conf
`)
}

func renderIKEv2Unit(conf, daemonConf string) []byte {
	return renderIPsecUnit(conf, daemonConf, true)
}

func renderIPsecUnit(conf, daemonConf string, hasIKEv2 bool) []byte {
	dependencies := "network-online.target"
	if hasIKEv2 {
		dependencies += " netos-ikev2-auth.service"
	}
	return []byte(`[Unit]
Description=netOS: IPsec servers
After=` + dependencies + `
Wants=` + dependencies + `

[Service]
Type=notify
Environment=STRONGSWAN_CONF=` + daemonConf + `
ExecStart=/usr/sbin/charon-systemd
ExecStartPost=/usr/sbin/swanctl --load-all --uri unix:///run/netos-strongswan/charon.vici --file ` + conf + ` --noprompt
ExecReload=/usr/sbin/swanctl --load-all --uri unix:///run/netos-strongswan/charon.vici --file ` + conf + ` --noprompt
Restart=on-failure
RestartSec=5
RuntimeDirectory=netos-strongswan
RuntimeDirectoryMode=0755
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW

[Install]
WantedBy=multi-user.target
`)
}

func (s *Subsystem) ensureIKEv2Interface(ctx context.Context, server config.VPNServer, wasOwned bool) (bool, error) {
	name := InterfaceName(server)
	existed := s.linkExists(name)
	if existed && !wasOwned {
		return false, fmt.Errorf("интерфейс %s существует и не принадлежит netOS", name)
	}
	if !existed {
		if _, err := s.Runner.Run(ctx, "ip", "link", "add", name, "type", "xfrm", "if_id", fmt.Sprint(50000+server.Index)); err != nil {
			return false, fmt.Errorf("создание XFRM-интерфейса: %w", err)
		}
	}
	if err := s.ensureAddress(ctx, name, server.Subnet); err != nil {
		if !existed {
			_, _ = s.Runner.Run(ctx, "ip", "link", "delete", name)
		}
		return false, err
	}
	ike, _ := server.IKEv2Config()
	mtu := ike.MTU
	if mtu == 0 {
		mtu = 1400
	}
	linkOut, linkErr := s.Runner.Run(ctx, "ip", "-o", "link", "show", "dev", name)
	up, currentMTU := vpnLinkState(linkOut)
	if linkErr != nil || !up || currentMTU != mtu {
		if _, err := s.Runner.Run(ctx, "ip", "link", "set", "dev", name, "mtu", fmt.Sprint(mtu), "up"); err != nil {
			return false, err
		}
	}
	return !existed, nil
}

func (s *Subsystem) applyIKEv2(ctx context.Context, cfg *config.Config, servers []config.VPNServer, unitWasOwned bool) (retErr error) {
	paths := s.ikev2Paths()
	l2tp := l2tpIPsecServers(cfg)
	if len(servers) == 0 && len(l2tp) == 0 {
		return s.cleanupIKEv2(ctx)
	}
	_, unitStatErr := os.Stat(paths.unit)
	unitExisted := unitStatErr == nil
	_, authStatErr := os.Stat(paths.authUnit)
	authExisted := authStatErr == nil
	if authExisted && !unitWasOwned {
		return fmt.Errorf("служба %s уже существует и не принадлежит netOS", ikev2AuthUnit)
	} else if authStatErr != nil && !os.IsNotExist(authStatErr) {
		return authStatErr
	}
	if unitExisted && !unitWasOwned {
		return fmt.Errorf("служба %s уже существует и не принадлежит netOS", ikev2Unit)
	} else if unitStatErr != nil && !os.IsNotExist(unitStatErr) {
		return unitStatErr
	}
	snapshotPaths := []string{paths.root, paths.unit, paths.authUnit}
	for _, profile := range ikeArmorProfiles {
		snapshotPaths = append(snapshotPaths, filepath.Join(s.AppArmorDir, "local", profile))
	}
	snapshots, err := capturePaths(snapshotPaths...)
	if err != nil {
		return err
	}
	servicesTouched := false
	defer func() {
		if retErr == nil {
			return
		}
		if !unitExisted {
			if err := s.cleanupIKEv2(context.Background()); err != nil {
				retErr = fmt.Errorf("%v; восстановление AppArmor: %w", retErr, err)
			}
			return
		}
		if err := restorePaths(snapshots); err != nil {
			retErr = fmt.Errorf("%v; восстановление IKEv2: %w", retErr, err)
			return
		}
		if !authExisted {
			_, _ = s.Runner.Run(context.Background(), "systemctl", "disable", "--now", ikev2AuthUnit)
		}
		if err := reloadIKEArmor(context.Background(), s.AppArmorDir, s.AppArmorProfiles, s.Runner.Run); err != nil {
			retErr = fmt.Errorf("%v; восстановление AppArmor: %w", retErr, err)
			return
		}
		_, _ = s.Runner.Run(context.Background(), "systemctl", "daemon-reload")
		if authExisted && servicesTouched {
			_, _ = s.Runner.Run(context.Background(), "systemctl", "restart", ikev2AuthUnit)
		}
		if servicesTouched {
			_, _ = s.Runner.Run(context.Background(), "systemctl", "restart", ikev2Unit)
		}
	}()
	if err := s.ensureIKEArmor(ctx); err != nil {
		return fmt.Errorf("разрешения AppArmor IKEv2: %w", err)
	}
	dirs := []string{paths.root}
	if len(servers) > 0 {
		dirs = append(dirs, paths.authRoot, filepath.Dir(paths.cert), filepath.Dir(paths.key))
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	authSecret := ""
	authChanged, certChanged := false, false
	if len(servers) > 0 {
		authSecret, err = ensureIKEv2AuthSecret(paths.root)
		if err != nil {
			return err
		}
		authUsers, err := renderIKEv2AuthUsers(servers)
		if err != nil {
			return err
		}
		authConf := renderIKEv2AuthConfig(paths.authRoot, authSecret)
		authUnit := renderIKEv2AuthUnit(paths.authRoot)
		for _, file := range []struct {
			path string
			data []byte
			mode os.FileMode
		}{
			{filepath.Join(paths.authRoot, "dictionary"), []byte(ikev2AuthDictionary), 0o600},
			{filepath.Join(paths.authRoot, "users"), authUsers, 0o600},
			{filepath.Join(paths.authRoot, "radiusd.conf"), authConf, 0o600},
			{paths.authUnit, authUnit, 0o644},
		} {
			authChanged = authChanged || system.FileChanged(file.path, file.data)
			if err := writeFile(file.path, file.data, file.mode); err != nil {
				return err
			}
		}
		if authChanged {
			if _, err := s.Runner.Run(ctx, "/usr/sbin/freeradius", "-C", "-lstdout", "-d", paths.authRoot); err != nil {
				return fmt.Errorf("проверка авторизации IKEv2: %w", err)
			}
		}
		var names []string
		for _, server := range servers {
			names = append(names, ikev2Identity(server, cfg))
		}
		sourceCert, sourceKey, _, err := tlsutil.EnsureSelfSignedForNames(paths.sourceTLS, cfg.System.Hostname, names...)
		if err != nil {
			return fmt.Errorf("сертификат IKEv2: %w", err)
		}
		certData, err := os.ReadFile(sourceCert)
		if err != nil {
			return err
		}
		keyData, err := os.ReadFile(sourceKey)
		if err != nil {
			return err
		}
		certChanged = system.FileChanged(paths.cert, certData) || system.FileChanged(paths.key, keyData)
		if err := writeFile(paths.cert, certData, 0o644); err != nil {
			return err
		}
		if err := writeFile(paths.key, keyData, 0o600); err != nil {
			return err
		}
	} else if authExisted {
		servicesTouched = true
		if _, err := s.Runner.Run(ctx, "systemctl", "disable", "--now", ikev2AuthUnit); err != nil {
			return err
		}
		for _, path := range []string{paths.authUnit, paths.authRoot, paths.sourceTLS, paths.cert, paths.key, filepath.Join(paths.root, "radius.secret")} {
			if err := os.RemoveAll(path); err != nil {
				return err
			}
		}
		authChanged = true
	}

	conf, err := renderIPsecServers(servers, cfg, l2tp)
	if err != nil {
		return err
	}
	if err := system.WriteFileAtomic(paths.candidate, conf, 0o600); err != nil {
		return err
	}
	defer os.Remove(paths.candidate)
	daemonConf := renderIKEv2DaemonConfig(authSecret)
	daemonChanged := system.FileChanged(paths.daemonConf, daemonConf)
	if err := writeFile(paths.daemonConf, daemonConf, 0o600); err != nil {
		return err
	}
	unit := renderIPsecUnit(paths.conf, paths.daemonConf, len(servers) > 0)
	unitChanged := system.FileChanged(paths.unit, unit)
	confChanged := system.FileChanged(paths.conf, conf)
	if err := writeFile(paths.unit, unit, 0o644); err != nil {
		return err
	}
	active, _ := s.Runner.Run(ctx, "systemctl", "is-active", ikev2Unit)
	if err := writeFile(paths.conf, conf, 0o600); err != nil {
		return err
	}
	if unitChanged || authChanged {
		if _, err := s.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	if err := s.ensureUnitEnabled(ctx, ikev2Unit); err != nil {
		return err
	}
	if len(servers) > 0 {
		if err := s.ensureUnitEnabled(ctx, ikev2AuthUnit); err != nil {
			return err
		}
		authActive, _ := s.Runner.Run(ctx, "systemctl", "is-active", ikev2AuthUnit)
		if authChanged || strings.TrimSpace(authActive) != "active" {
			servicesTouched = true
			if _, err := s.Runner.Run(ctx, "systemctl", "restart", ikev2AuthUnit); err != nil {
				return fmt.Errorf("запуск авторизации IKEv2: %w", err)
			}
		}
	}

	// Preserve the existing revocation semantics: credential/IP changes also
	// disconnect established sessions. Rollback restores both services.
	if unitChanged || daemonChanged || confChanged || authChanged || certChanged || strings.TrimSpace(active) != "active" {
		servicesTouched = true
		if _, err := s.Runner.Run(ctx, "systemctl", "restart", ikev2Unit); err != nil {
			if strings.TrimSpace(active) != "active" {
				s.cleanupIKEv2(ctx)
			}
			return fmt.Errorf("запуск strongSwan: %w", err)
		}
	}
	return s.terminateRevokedIKEv2(ctx, servers)
}

// terminateRevokedIKEv2 завершает соединения отозванных пользователей.
//
// Перечитывание конфигурации удаляет их учётные данные, но уже установленную
// пару SA не трогает: снятый в панели флаг «Разрешён» оставлял пользователю
// работающий доступ к сети до тех пор, пока соединение не разорвётся само.
// Администратор при этом видел доступ отозванным.
func (s *Subsystem) terminateRevokedIKEv2(ctx context.Context, servers []config.VPNServer) error {
	if strings.TrimSpace(s.runQuiet(ctx, "systemctl", "is-active", ikev2Unit)) != "active" {
		return nil
	}
	allowed := map[string]bool{}
	for _, server := range servers {
		for _, peer := range server.Peers {
			if peer.Enabled {
				if id := peer.Credentials["username"]; id != "" {
					allowed[id] = true
				}
			}
		}
	}
	list, err := s.Runner.Run(ctx, "/usr/sbin/swanctl", "--list-sas", "--raw",
		"--uri", "unix:///run/netos-strongswan/charon.vici")
	if err != nil {
		return fmt.Errorf("чтение установленных соединений IKEv2: %w", err)
	}
	for _, sa := range parseIKEv2SAs(list) {
		if sa.version == "1" || sa.uniqueID == "" || allowed[sa.identity] {
			continue
		}
		if output, err := s.Runner.Run(ctx, "/usr/sbin/swanctl", "--terminate", "--ike-id", sa.uniqueID,
			"--uri", "unix:///run/netos-strongswan/charon.vici"); err != nil {
			// The client may disconnect between list-sas and terminate.
			if strings.Contains(output, "no matching SAs to terminate found") {
				continue
			}
			return fmt.Errorf("разрыв соединения отозванного пользователя IKEv2: %w", err)
		}
	}
	return nil
}

type ikev2SA struct {
	uniqueID string
	identity string
	version  string
}

// parseIKEv2SAs достаёт из машинного вывода swanctl номер соединения и то, под
// какой учётной записью оно установлено. CHILD_SA имеет собственный uniqueid
// во вложенной секции: он не является номером IKE_SA. EAP identity важнее
// remote-id, который клиент вправе задать отличным от имени пользователя.
func parseIKEv2SAs(raw string) []ikev2SA {
	var out []ikev2SA
	current := ikev2SA{}
	depth, identityPriority := 0, 0
	for _, token := range strings.Fields(strings.NewReplacer("{", " { ", "}", " } ").Replace(raw)) {
		switch token {
		case "{":
			depth++
			if depth == 2 {
				current = ikev2SA{}
				identityPriority = 0
			}
			continue
		case "}":
			if depth == 2 && current.uniqueID != "" {
				out = append(out, current)
			}
			depth--
			continue
		}
		if depth != 2 {
			continue
		}
		key, value, ok := strings.Cut(token, "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, `"`)
		switch key {
		case "version":
			current.version = value
		case "uniqueid":
			current.uniqueID = value
		case "remote-eap-id", "remote-xauth-id", "remote-id":
			priority := map[string]int{"remote-id": 1, "remote-xauth-id": 2, "remote-eap-id": 3}[key]
			if value != "" && priority > identityPriority {
				current.identity = value
				identityPriority = priority
			}
		}
	}
	return out
}

// runQuiet возвращает вывод команды, не превращая ненулевой код в ошибку:
// systemctl сообщает состояние и им, и текстом.
func (s *Subsystem) runQuiet(ctx context.Context, name string, args ...string) string {
	out, _ := s.Runner.Run(ctx, name, args...)
	return out
}

func (s *Subsystem) cleanupIKEv2(ctx context.Context) error {
	paths := s.ikev2Paths()
	if _, unitErr := os.Stat(paths.unit); os.IsNotExist(unitErr) {
		if _, rootErr := os.Stat(paths.root); os.IsNotExist(rootErr) {
			if _, authErr := os.Stat(paths.authUnit); os.IsNotExist(authErr) {
				return RemoveIKEv2AppArmor(ctx, s.AppArmorDir, s.AppArmorProfiles, s.Runner.Run)
			}
		}
	}
	_, _ = s.Runner.Run(ctx, "systemctl", "disable", ikev2Unit)
	_, _ = s.Runner.Run(ctx, "systemctl", "stop", ikev2Unit)
	_, _ = s.Runner.Run(ctx, "systemctl", "disable", ikev2AuthUnit)
	_, _ = s.Runner.Run(ctx, "systemctl", "stop", ikev2AuthUnit)
	_ = os.Remove(paths.unit)
	_ = os.Remove(paths.authUnit)
	_ = os.RemoveAll(paths.root)
	_, _ = s.Runner.Run(ctx, "systemctl", "daemon-reload")
	return RemoveIKEv2AppArmor(ctx, s.AppArmorDir, s.AppArmorProfiles, s.Runner.Run)
}
