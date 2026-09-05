package vpnservers

import (
	"context"
	"encoding/base64"
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
}

func (s *Subsystem) ikev2Paths() ikev2Paths {
	root := filepath.Join(s.StateDir, "strongswan")
	return ikev2Paths{
		root: root, conf: filepath.Join(root, "swanctl.conf"), candidate: filepath.Join(root, "swanctl.conf.candidate"),
		daemonConf: filepath.Join(root, "strongswan.conf"),
		cert:       filepath.Join(root, "x509", "server.crt"), key: filepath.Join(root, "private", "server.key"),
		sourceTLS: filepath.Join(root, "tls"), unit: filepath.Join(s.UnitDir, ikev2Unit),
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

func ikev2Pool(server config.VPNServer) (string, error) {
	var address netip.Addr
	enabled := 0
	for _, peer := range server.Peers {
		if !peer.Enabled {
			continue
		}
		parsed, err := netip.ParseAddr(peer.Address)
		if err != nil {
			return "", err
		}
		enabled++
		if enabled > 1 {
			return "", fmt.Errorf("IKEv2 поддерживает только одного активного пользователя: пакет strongSwan не умеет фиксировать адрес пула за EAP-учётной записью")
		}
		address = parsed
	}
	if enabled == 0 {
		prefix, err := netip.ParsePrefix(server.Subnet)
		if err != nil {
			return "", err
		}
		return prefix.Addr().Next().String(), nil
	}
	return address.String(), nil
}

// RenderIKEv2 returns one swanctl configuration for all listeners. strongSwan
// owns the standard UDP ports globally, while each connection is tied to its
// own XFRM interface ID and address pool.
func RenderIKEv2(servers []config.VPNServer, cfg *config.Config) ([]byte, error) {
	var b strings.Builder
	fmt.Fprintln(&b, "# Сгенерировано netOS. Файл содержит EAP-секреты; права 0600.")
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
		}
		fmt.Fprintf(&b, "  netos-srv%d {\n", server.Index)
		fmt.Fprintln(&b, "    version = 2")
		fmt.Fprintln(&b, "    local_addrs = 0.0.0.0")
		fmt.Fprintf(&b, "    pools = netos-srv%d\n", server.Index)
		fmt.Fprintln(&b, "    proposals = aes256gcm16-prfsha384-ecp384,aes256-sha256-modp2048")
		fmt.Fprintln(&b, "    fragmentation = yes")
		fmt.Fprintln(&b, "    mobike = yes")
		fmt.Fprintln(&b, "    local {")
		fmt.Fprintln(&b, "      auth = pubkey")
		fmt.Fprintln(&b, "      certs = server.crt")
		fmt.Fprintf(&b, "      id = %s\n", identity)
		fmt.Fprintln(&b, "    }")
		fmt.Fprintln(&b, "    remote {")
		fmt.Fprintln(&b, "      auth = eap-mschapv2")
		fmt.Fprintln(&b, "      eap_id = %any")
		fmt.Fprintln(&b, "    }")
		fmt.Fprintln(&b, "    children {")
		fmt.Fprintf(&b, "      netos-srv%d {\n", server.Index)
		fmt.Fprintf(&b, "        local_ts = %s\n", strings.Join(ts, ", "))
		// Only outbound policies need the interface ID. Inbound IKEv2 traffic
		// arrives on the physical interface after IPsec processing; attaching an
		// inbound ID breaks UDP encapsulation on strongSwan 6.0.1.
		fmt.Fprintf(&b, "        if_id_out = %d\n", 50000+server.Index)
		fmt.Fprintln(&b, "        esp_proposals = aes256gcm16-ecp384,aes256-sha256-modp2048")
		fmt.Fprintln(&b, "        dpd_action = clear")
		fmt.Fprintln(&b, "        close_action = clear")
		fmt.Fprintln(&b, "      }")
		fmt.Fprintln(&b, "    }")
		fmt.Fprintln(&b, "  }")
	}
	fmt.Fprintln(&b, "}")
	fmt.Fprintln(&b, "pools {")
	for _, server := range servers {
		ike, _ := server.IKEv2Config()
		pool, err := ikev2Pool(server)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "  netos-srv%d {\n", server.Index)
		fmt.Fprintf(&b, "    addrs = %s\n", pool)
		if len(ike.DNS) > 0 {
			fmt.Fprintf(&b, "    dns = %s\n", strings.Join(ike.DNS, ", "))
		}
		if len(ike.SplitRoutes) > 0 {
			fmt.Fprintf(&b, "    split_include = %s\n", strings.Join(ike.SplitRoutes, ", "))
		}
		fmt.Fprintln(&b, "  }")
	}
	fmt.Fprintln(&b, "}")
	fmt.Fprintln(&b, "secrets {")
	for _, server := range servers {
		for _, peer := range server.Peers {
			if !peer.Enabled {
				continue
			}
			secret := base64.StdEncoding.EncodeToString([]byte(peer.Credentials["password"]))
			fmt.Fprintf(&b, "  eap-srv%d-%s {\n", server.Index, peer.Credentials["username"])
			fmt.Fprintf(&b, "    id = %s\n", peer.Credentials["username"])
			fmt.Fprintf(&b, "    secret = 0s%s\n", secret)
			fmt.Fprintln(&b, "  }")
		}
	}
	fmt.Fprintln(&b, "}")
	return []byte(b.String()), nil
}

func renderIKEv2DaemonConfig() []byte {
	return []byte(`charon {
	load_modular = yes
  plugins {
	include /etc/strongswan.d/charon/*.conf
    vici {
      socket = unix:///run/netos-strongswan/charon.vici
    }
  }
}
include /etc/strongswan.d/*.conf
`)
}

func renderIKEv2Unit(conf, daemonConf string) []byte {
	return []byte(`[Unit]
Description=netOS: strongSwan IKEv2 servers
After=network-online.target
Wants=network-online.target

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
	if len(servers) == 0 {
		s.cleanupIKEv2(ctx)
		return nil
	}
	_, unitStatErr := os.Stat(paths.unit)
	unitExisted := unitStatErr == nil
	if unitExisted && !unitWasOwned {
		return fmt.Errorf("служба %s уже существует и не принадлежит netOS", ikev2Unit)
	} else if unitStatErr != nil && !os.IsNotExist(unitStatErr) {
		return unitStatErr
	}
	snapshots, err := capturePaths(paths.root, paths.unit)
	if err != nil {
		return err
	}
	mutated := true
	defer func() {
		if retErr == nil || !mutated {
			return
		}
		if !unitExisted {
			s.cleanupIKEv2(context.Background())
			return
		}
		if err := restorePaths(snapshots); err != nil {
			retErr = fmt.Errorf("%v; восстановление IKEv2: %w", retErr, err)
			return
		}
		_, _ = s.Runner.Run(context.Background(), "systemctl", "daemon-reload")
		_, _ = s.Runner.Run(context.Background(), "systemctl", "restart", ikev2Unit)
	}()
	for _, dir := range []string{paths.root, filepath.Dir(paths.cert), filepath.Dir(paths.key)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
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
	certChanged := system.FileChanged(paths.cert, certData) || system.FileChanged(paths.key, keyData)
	if err := writeFile(paths.cert, certData, 0o644); err != nil {
		return err
	}
	if err := writeFile(paths.key, keyData, 0o600); err != nil {
		return err
	}
	conf, err := RenderIKEv2(servers, cfg)
	if err != nil {
		return err
	}
	if err := system.WriteFileAtomic(paths.candidate, conf, 0o600); err != nil {
		return err
	}
	defer os.Remove(paths.candidate)
	daemonConf := renderIKEv2DaemonConfig()
	daemonChanged := system.FileChanged(paths.daemonConf, daemonConf)
	if err := writeFile(paths.daemonConf, daemonConf, 0o600); err != nil {
		return err
	}
	unit := renderIKEv2Unit(paths.conf, paths.daemonConf)
	unitChanged := system.FileChanged(paths.unit, unit)
	confChanged := system.FileChanged(paths.conf, conf)
	if err := writeFile(paths.unit, unit, 0o644); err != nil {
		return err
	}
	active, _ := s.Runner.Run(ctx, "systemctl", "is-active", ikev2Unit)
	if strings.TrimSpace(active) == "active" && (confChanged || certChanged) {
		if _, err := s.Runner.Run(ctx, "/usr/sbin/swanctl", "--load-all", "--uri", "unix:///run/netos-strongswan/charon.vici", "--file", paths.candidate, "--noprompt"); err != nil {
			return fmt.Errorf("проверка конфигурации strongSwan: %w", err)
		}
	}
	if err := writeFile(paths.conf, conf, 0o600); err != nil {
		return err
	}
	if unitChanged {
		if _, err := s.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	if err := s.ensureUnitEnabled(ctx, ikev2Unit); err != nil {
		return err
	}
	if unitChanged || daemonChanged || strings.TrimSpace(active) != "active" {
		if _, err := s.Runner.Run(ctx, "systemctl", "restart", ikev2Unit); err != nil {
			if strings.TrimSpace(active) != "active" {
				s.cleanupIKEv2(ctx)
			}
			return fmt.Errorf("запуск strongSwan: %w", err)
		}
	} else if confChanged || certChanged {
		if _, err := s.Runner.Run(ctx, "/usr/sbin/swanctl", "--load-all", "--uri", "unix:///run/netos-strongswan/charon.vici", "--file", paths.conf, "--noprompt"); err != nil {
			return err
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
		if sa.uniqueID == "" || allowed[sa.identity] {
			continue
		}
		if _, err := s.Runner.Run(ctx, "/usr/sbin/swanctl", "--terminate", "--ike-id", sa.uniqueID,
			"--uri", "unix:///run/netos-strongswan/charon.vici"); err != nil {
			return fmt.Errorf("разрыв соединения отозванного пользователя IKEv2: %w", err)
		}
	}
	return nil
}

type ikev2SA struct {
	uniqueID string
	identity string
}

// parseIKEv2SAs достаёт из машинного вывода swanctl номер соединения и то, под
// какой учётной записью оно установлено. Формат --raw — плоские пары
// ключ=значение, и нужны из них ровно две.
func parseIKEv2SAs(raw string) []ikev2SA {
	var out []ikev2SA
	current := ikev2SA{}
	flush := func() {
		if current.uniqueID != "" {
			out = append(out, current)
		}
		current = ikev2SA{}
	}
	for _, token := range strings.Fields(raw) {
		key, value, ok := strings.Cut(strings.Trim(token, "[]{},"), "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, `"`)
		switch key {
		case "uniqueid":
			flush()
			current.uniqueID = value
		case "remote-eap-id", "remote-xauth-id", "remote-id":
			if current.identity == "" {
				current.identity = value
			}
		}
	}
	flush()
	return out
}

// runQuiet возвращает вывод команды, не превращая ненулевой код в ошибку:
// systemctl сообщает состояние и им, и текстом.
func (s *Subsystem) runQuiet(ctx context.Context, name string, args ...string) string {
	out, _ := s.Runner.Run(ctx, name, args...)
	return out
}

func (s *Subsystem) cleanupIKEv2(ctx context.Context) {
	paths := s.ikev2Paths()
	if _, unitErr := os.Stat(paths.unit); os.IsNotExist(unitErr) {
		if _, rootErr := os.Stat(paths.root); os.IsNotExist(rootErr) {
			return
		}
	}
	_, _ = s.Runner.Run(ctx, "systemctl", "disable", ikev2Unit)
	_, _ = s.Runner.Run(ctx, "systemctl", "stop", ikev2Unit)
	_ = os.Remove(paths.unit)
	_ = os.RemoveAll(paths.root)
	_, _ = s.Runner.Run(ctx, "systemctl", "daemon-reload")
}
