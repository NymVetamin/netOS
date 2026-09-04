// Package vpnservers manages inbound VPN interfaces.
package vpnservers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"sort"
	"strings"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
	"github.com/netos-router/netos/internal/tlsutil"
)

type ownedServer struct {
	Name  string `json:"name"`
	Index int    `json:"index"`
	Type  string `json:"type,omitempty"`
	Unit  string `json:"unit,omitempty"`
}

type snapshotEntry struct {
	rel    string
	mode   os.FileMode
	data   []byte
	link   string
	isDir  bool
	isLink bool
}

type pathSnapshot struct {
	path    string
	existed bool
	entries []snapshotEntry
}

func capturePaths(paths ...string) ([]pathSnapshot, error) {
	result := make([]pathSnapshot, 0, len(paths))
	for _, path := range paths {
		snapshot := pathSnapshot{path: path}
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			result = append(result, snapshot)
			continue
		}
		if err != nil {
			return nil, err
		}
		snapshot.existed = true
		add := func(fullPath, rel string, info os.FileInfo) error {
			entry := snapshotEntry{rel: rel, mode: info.Mode(), isDir: info.IsDir()}
			if info.Mode()&os.ModeSymlink != 0 {
				entry.isLink = true
				entry.link, err = os.Readlink(fullPath)
			} else if !info.IsDir() {
				entry.data, err = os.ReadFile(fullPath)
			}
			if err == nil {
				snapshot.entries = append(snapshot.entries, entry)
			}
			return err
		}
		if !info.IsDir() {
			if err := add(path, ".", info); err != nil {
				return nil, err
			}
		} else if err := filepath.Walk(path, func(current string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, err := filepath.Rel(path, current)
			if err != nil {
				return err
			}
			return add(current, rel, info)
		}); err != nil {
			return nil, err
		}
		result = append(result, snapshot)
	}
	return result, nil
}

func restorePaths(snapshots []pathSnapshot) error {
	for _, snapshot := range snapshots {
		if err := os.RemoveAll(snapshot.path); err != nil {
			return err
		}
		if !snapshot.existed {
			continue
		}
		for _, entry := range snapshot.entries {
			target := snapshot.path
			if entry.rel != "." {
				target = filepath.Join(snapshot.path, entry.rel)
			}
			switch {
			case entry.isDir:
				if err := os.MkdirAll(target, entry.mode.Perm()); err != nil {
					return err
				}
			case entry.isLink:
				if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
					return err
				}
				if err := os.Symlink(entry.link, target); err != nil {
					return err
				}
			default:
				if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
					return err
				}
				if err := os.WriteFile(target, entry.data, entry.mode.Perm()); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

type Subsystem struct {
	Runner      system.Runner
	StateDir    string
	SysClassNet string
	ProcSysNet  string
	UnitDir     string
}

func New(r system.Runner, stateDir string) *Subsystem {
	return &Subsystem{Runner: r, StateDir: stateDir, SysClassNet: "/sys/class/net", ProcSysNet: "/proc/sys/net", UnitDir: "/etc/systemd/system"}
}

func (s *Subsystem) Name() string { return "vpn-servers" }

func InterfaceName(server config.VPNServer) string {
	switch server.Type {
	case "ocserv":
		return fmt.Sprintf("vpns%d", server.Index)
	case "ikev2":
		return fmt.Sprintf("xfrm-srv%d", server.Index)
	default:
		return fmt.Sprintf("wg-srv%d", server.Index)
	}
}

func resourceName(server config.VPNServer) string {
	if server.Type == "xray" {
		return fmt.Sprintf("xray-srv%d", server.Index)
	}
	if server.Type == "ocserv" {
		return fmt.Sprintf("ocserv-srv%d", server.Index)
	}
	return InterfaceName(server)
}

func enabledServers(cfg *config.Config) []config.VPNServer {
	var out []config.VPNServer
	for _, server := range cfg.VPNServers {
		if server.Enabled && (server.Type == "wireguard" || server.Type == "xray" || server.Type == "ocserv" || server.Type == "ikev2") {
			out = append(out, server)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

func ownedServersFor(servers []config.VPNServer) []ownedServer {
	items := make([]ownedServer, 0, len(servers))
	for _, server := range servers {
		item := ownedServer{Name: resourceName(server), Index: server.Index, Type: server.Type}
		switch server.Type {
		case "xray":
			item.Unit = xrayUnitName(server)
		case "ocserv":
			item.Unit = ocservUnitName(server)
		case "ikev2":
			item.Unit = ikev2Unit
		}
		items = append(items, item)
	}
	return items
}

func ownedServersEqual(left, right []ownedServer) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func (s *Subsystem) Plan(old, next *config.Config) ([]apply.Action, error) {
	return s.PlanContext(context.Background(), old, next)
}

func (s *Subsystem) PlanContext(ctx context.Context, old, next *config.Config) ([]apply.Action, error) {
	wanted := enabledServers(next)
	previous := map[string]config.VPNServer{}
	if old != nil {
		for _, server := range enabledServers(old) {
			previous[server.ID] = server
		}
	}
	var actions []apply.Action
	for _, server := range wanted {
		before, exists := previous[server.ID]
		delete(previous, server.ID)
		kind := "create"
		if exists {
			if reflect.DeepEqual(before, server) {
				continue
			}
			kind = "update"
		}
		actions = append(actions, apply.Action{Kind: kind, Target: server.Name, Detail: resourceName(server), Disruptive: true})
	}
	for _, server := range previous {
		actions = append(actions, apply.Action{Kind: "delete", Target: server.Name, Detail: resourceName(server), Disruptive: true})
	}
	if old != nil && len(actions) == 0 {
		if err := s.Health(ctx, next); err != nil {
			actions = append(actions, apply.Action{
				Kind: "update", Target: "живое состояние VPN-серверов", Detail: err.Error(), Disruptive: true,
			})
		}
	}
	return actions, nil
}

func (s *Subsystem) Apply(ctx context.Context, cfg *config.Config) error {
	wanted := enabledServers(cfg)
	owned, err := s.readOwned()
	if err != nil {
		return err
	}
	wantedOwned := map[string]ownedServer{}
	for _, item := range ownedServersFor(wanted) {
		wantedOwned[item.Name] = item
	}
	retained := map[string]bool{}
	ikeUnitOwned := false
	for _, item := range owned {
		if item.Type == "ikev2" && (item.Unit == "" || item.Unit == ikev2Unit) {
			ikeUnitOwned = true
		}
		expected, exists := wantedOwned[item.Name]
		if exists && item.Type == expected.Type && item.Unit == expected.Unit {
			retained[item.Name] = true
			continue
		}
		if err := s.remove(ctx, item); err != nil {
			return fmt.Errorf("удаление старого VPN-сервера %s: %w", item.Name, err)
		}
	}
	var nextOwned []ownedServer
	var created []ownedServer
	for _, server := range wanted {
		item := ownedServer{Name: resourceName(server), Index: server.Index, Type: server.Type}
		var createdNow bool
		switch server.Type {
		case "wireguard":
			createdNow, err = s.applyWireGuard(ctx, server, retained[item.Name], cfg.IPv6.Mode == "off")
		case "xray":
			item.Unit = xrayUnitName(server)
			createdNow, err = s.applyXray(ctx, cfg, server, retained[item.Name])
		case "ocserv":
			item.Unit = ocservUnitName(server)
			createdNow, err = s.applyOcserv(ctx, cfg, server, retained[item.Name])
		case "ikev2":
			item.Unit = ikev2Unit
			createdNow, err = s.ensureIKEv2Interface(ctx, server, retained[item.Name])
		}
		if err != nil {
			for _, provisional := range created {
				s.remove(ctx, provisional)
			}
			return fmt.Errorf("VPN-сервер %s: %w", server.Name, err)
		}
		if createdNow {
			created = append(created, item)
		}
		nextOwned = append(nextOwned, item)
	}
	if err := s.applyIKEv2(ctx, cfg, ikev2Servers(cfg), ikeUnitOwned); err != nil {
		for _, provisional := range created {
			s.remove(ctx, provisional)
		}
		return fmt.Errorf("сервер IKEv2: %w", err)
	}
	if err := s.writeOwned(nextOwned); err != nil {
		for _, provisional := range created {
			s.remove(ctx, provisional)
		}
		return err
	}
	return nil
}

func RenderWireGuard(server config.VPNServer) (string, error) {
	wg, err := server.WireGuardConfig()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintln(&b, "# Сгенерировано netOS. Файл содержит секреты; права 0600.")
	fmt.Fprintln(&b, "[Interface]")
	fmt.Fprintf(&b, "PrivateKey = %s\n", wg.PrivateKey)
	fmt.Fprintf(&b, "ListenPort = %d\n", server.Port)
	for _, peer := range server.Peers {
		if !peer.Enabled {
			continue
		}
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "[Peer]")
		fmt.Fprintf(&b, "# %s\n", strings.ReplaceAll(peer.Name, "\n", " "))
		fmt.Fprintf(&b, "PublicKey = %s\n", peer.Credentials["public_key"])
		if key := peer.Credentials["preshared_key"]; key != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", key)
		}
		fmt.Fprintf(&b, "AllowedIPs = %s/32\n", peer.Address)
	}
	return b.String(), nil
}

func (s *Subsystem) applyWireGuard(ctx context.Context, server config.VPNServer, wasOwned, disableIPv6 bool) (bool, error) {
	name := InterfaceName(server)
	existed := s.linkExists(name)
	if existed && !wasOwned {
		return false, fmt.Errorf("интерфейс %s существует и не принадлежит netOS", name)
	}
	if existed {
		if _, err := s.Runner.Run(ctx, "wg", "show", name); err != nil {
			return false, fmt.Errorf("интерфейс %s не является WireGuard", name)
		}
	}
	conf, err := RenderWireGuard(server)
	if err != nil {
		return false, err
	}
	path := filepath.Join(s.StateDir, name+".conf")
	if err := writeFile(path, []byte(conf), 0o600); err != nil {
		return false, fmt.Errorf("сохранение конфигурации: %w", err)
	}
	if !existed {
		if _, err := s.Runner.Run(ctx, "ip", "link", "add", "name", name, "type", "wireguard"); err != nil {
			_ = os.Remove(path)
			return false, fmt.Errorf("создание интерфейса: %w", err)
		}
	}
	created := !existed
	fail := func(err error) (bool, error) {
		if created {
			s.remove(ctx, ownedServer{Name: name, Index: server.Index})
		}
		return false, err
	}
	if _, err := s.Runner.Run(ctx, "wg", "syncconf", name, path); err != nil {
		return fail(fmt.Errorf("настройка WireGuard: %w", err))
	}
	if err := s.ensureAddress(ctx, name, server.Subnet); err != nil {
		return fail(err)
	}
	wg, _ := server.WireGuardConfig()
	mtu := wg.MTU
	if mtu == 0 {
		mtu = 1420
	}
	linkOut, linkErr := s.Runner.Run(ctx, "ip", "-o", "link", "show", "dev", name)
	up, currentMTU := vpnLinkState(linkOut)
	if linkErr != nil || !up || currentMTU != mtu {
		if _, err := s.Runner.Run(ctx, "ip", "link", "set", "dev", name, "mtu", fmt.Sprint(mtu), "up"); err != nil {
			return fail(fmt.Errorf("поднятие интерфейса: %w", err))
		}
	}
	desiredIPv6Disable := "0"
	if disableIPv6 {
		desiredIPv6Disable = "1"
	}
	ipv6Path := filepath.Join(s.ProcSysNet, "ipv6", "conf", name, "disable_ipv6")
	current, readErr := os.ReadFile(ipv6Path)
	if readErr == nil && strings.TrimSpace(string(current)) != desiredIPv6Disable {
		if err := os.WriteFile(ipv6Path, []byte(desiredIPv6Disable), 0o644); err != nil {
			return fail(fmt.Errorf("настройка IPv6 на %s: %w", name, err))
		}
	} else if readErr != nil && !os.IsNotExist(readErr) {
		return fail(fmt.Errorf("чтение настройки IPv6 на %s: %w", name, readErr))
	}
	return created, nil
}

func vpnLinkState(out string) (up bool, mtu int) {
	fields := strings.Fields(out)
	for i, field := range fields {
		if strings.HasPrefix(field, "<") && strings.HasSuffix(field, ">") {
			for _, flag := range strings.Split(strings.Trim(field, "<>"), ",") {
				if flag == "UP" {
					up = true
				}
			}
		}
		if field == "mtu" && i+1 < len(fields) {
			_, _ = fmt.Sscan(fields[i+1], &mtu)
		}
	}
	return up, mtu
}

func (s *Subsystem) ensureAddress(ctx context.Context, name, address string) error {
	out, _ := s.Runner.Run(ctx, "ip", "-o", "-4", "addr", "show", "dev", name)
	if hasAddress(out, address) {
		return nil
	}
	if _, err := s.Runner.Run(ctx, "ip", "-4", "addr", "flush", "dev", name); err != nil {
		return fmt.Errorf("очистка адресов: %w", err)
	}
	if _, err := s.Runner.Run(ctx, "ip", "-4", "addr", "add", address, "dev", name); err != nil {
		return fmt.Errorf("назначение адреса: %w", err)
	}
	return nil
}

func hasAddress(out, address string) bool {
	for _, field := range strings.Fields(out) {
		if field == address {
			return true
		}
	}
	return false
}

func (s *Subsystem) Health(ctx context.Context, cfg *config.Config) error {
	wanted := enabledServers(cfg)
	owned, err := s.readOwned()
	if err != nil {
		return err
	}
	if !ownedServersEqual(owned, ownedServersFor(wanted)) {
		return fmt.Errorf("список принадлежащих netOS VPN-серверов расходится с конфигурацией")
	}
	ikeChecked := false
	for _, server := range wanted {
		if server.Type == "xray" {
			if err := s.unitActiveEnabled(ctx, xrayUnitName(server)); err != nil {
				return fmt.Errorf("сервер %s не работает", server.Name)
			}
			conf, err := RenderXray(server, cfg)
			if err != nil {
				return err
			}
			confPath, unitPath := s.xrayPaths(server)
			if err := healthyFile(confPath, conf, 0o600); err != nil {
				return err
			}
			if err := healthyFile(unitPath, []byte(renderXrayUnit(server, confPath)), 0o644); err != nil {
				return err
			}
			continue
		}
		if server.Type == "ocserv" {
			if err := s.unitActiveEnabled(ctx, ocservUnitName(server)); err != nil {
				return fmt.Errorf("сервер %s не работает", server.Name)
			}
			paths := s.ocservPaths(server)
			conf, err := RenderOcserv(server, cfg, s.StateDir)
			if err != nil {
				return err
			}
			if err := healthyFile(paths.conf, conf, 0o600); err != nil {
				return err
			}
			if err := healthyFile(paths.unit, []byte(renderOcservUnit(server, paths.conf)), 0o644); err != nil {
				return err
			}
			if err := ocservAuthHealth(paths, server); err != nil {
				return fmt.Errorf("учётные записи OpenConnect: %w", err)
			}
			if _, err := tlsutil.ValidatePairForNames(filepath.Join(paths.tls, "panel.crt"), filepath.Join(paths.tls, "panel.key"), cfg.System.Hostname); err != nil {
				return fmt.Errorf("TLS OpenConnect: %w", err)
			}
			continue
		}
		if server.Type == "ikev2" {
			if err := s.unitActiveEnabled(ctx, ikev2Unit); err != nil {
				return fmt.Errorf("сервер %s не работает", server.Name)
			}
			name := InterfaceName(server)
			if !s.linkExists(name) {
				return fmt.Errorf("интерфейс %s отсутствует", name)
			}
			ike, err := server.IKEv2Config()
			if err != nil {
				return err
			}
			expectedMTU := ike.MTU
			if expectedMTU == 0 {
				expectedMTU = 1400
			}
			linkOut, linkErr := s.Runner.Run(ctx, "ip", "-o", "link", "show", "dev", name)
			up, mtu := vpnLinkState(linkOut)
			if linkErr != nil || !up || mtu != expectedMTU {
				return fmt.Errorf("интерфейс %s: ожидаются UP и MTU %d", name, expectedMTU)
			}
			addrs, err := s.Runner.Run(ctx, "ip", "-o", "-4", "addr", "show", "dev", name)
			if err != nil || !hasAddress(addrs, server.Subnet) {
				return fmt.Errorf("на %s нет адреса %s", name, server.Subnet)
			}
			if !ikeChecked {
				servers := ikev2Servers(cfg)
				conf, err := RenderIKEv2(servers, cfg)
				if err != nil {
					return err
				}
				paths := s.ikev2Paths()
				for _, check := range []struct {
					path string
					data []byte
					mode os.FileMode
				}{
					{paths.conf, conf, 0o600},
					{paths.daemonConf, renderIKEv2DaemonConfig(), 0o600},
					{paths.unit, renderIKEv2Unit(paths.conf, paths.daemonConf), 0o644},
				} {
					if err := healthyFile(check.path, check.data, check.mode); err != nil {
						return err
					}
				}
				names := []string{cfg.System.Hostname}
				for _, item := range servers {
					names = append(names, ikev2Identity(item, cfg))
				}
				if _, err := tlsutil.ValidatePairForNames(paths.cert, paths.key, names...); err != nil {
					return fmt.Errorf("TLS IKEv2: %w", err)
				}
				ikeChecked = true
			}
			continue
		}
		name := InterfaceName(server)
		if !s.linkExists(name) {
			return fmt.Errorf("интерфейс %s отсутствует", name)
		}
		wg, err := server.WireGuardConfig()
		if err != nil {
			return err
		}
		expectedMTU := wg.MTU
		if expectedMTU == 0 {
			expectedMTU = 1420
		}
		linkOut, linkErr := s.Runner.Run(ctx, "ip", "-o", "link", "show", "dev", name)
		up, mtu := vpnLinkState(linkOut)
		if linkErr != nil || !up || mtu != expectedMTU {
			return fmt.Errorf("интерфейс %s: ожидаются UP и MTU %d", name, expectedMTU)
		}
		desiredIPv6Disable := "0"
		if cfg.IPv6.Mode == "off" {
			desiredIPv6Disable = "1"
		}
		ipv6Path := filepath.Join(s.ProcSysNet, "ipv6", "conf", name, "disable_ipv6")
		if current, err := os.ReadFile(ipv6Path); err == nil {
			if strings.TrimSpace(string(current)) != desiredIPv6Disable {
				return fmt.Errorf("интерфейс %s: disable_ipv6=%s вместо %s", name, strings.TrimSpace(string(current)), desiredIPv6Disable)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("интерфейс %s: чтение disable_ipv6: %w", name, err)
		}
		show, err := s.Runner.Run(ctx, "wg", "show", name, "listen-port")
		if err != nil || strings.TrimSpace(show) != fmt.Sprint(server.Port) {
			return fmt.Errorf("сервер %s не слушает UDP-порт %d", server.Name, server.Port)
		}
		addrs, err := s.Runner.Run(ctx, "ip", "-o", "-4", "addr", "show", "dev", name)
		if err != nil || !hasAddress(addrs, server.Subnet) {
			return fmt.Errorf("на %s нет адреса %s", name, server.Subnet)
		}
		conf, err := RenderWireGuard(server)
		if err != nil {
			return err
		}
		if err := healthyFile(filepath.Join(s.StateDir, name+".conf"), []byte(conf), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func healthyFile(path string, expected []byte, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("артефакт VPN %s не является обычным файлом без symlink", path)
	}
	if system.FileChanged(path, expected) {
		return fmt.Errorf("артефакт VPN %s расходится с конфигурацией", path)
	}
	if goruntime.GOOS != "windows" && info.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("права VPN-артефакта %s: %04o, ожидалось %04o", path, info.Mode().Perm(), mode.Perm())
	}
	return nil
}

func (s *Subsystem) ensureUnitEnabled(ctx context.Context, unit string) error {
	enabled, _ := s.Runner.Run(ctx, "systemctl", "is-enabled", unit)
	if strings.TrimSpace(enabled) == "enabled" {
		return nil
	}
	_, err := s.Runner.Run(ctx, "systemctl", "enable", unit)
	return err
}

func (s *Subsystem) unitActiveEnabled(ctx context.Context, unit string) error {
	active, _ := s.Runner.Run(ctx, "systemctl", "is-active", unit)
	if strings.TrimSpace(active) != "active" {
		return fmt.Errorf("служба %s не активна", unit)
	}
	enabled, _ := s.Runner.Run(ctx, "systemctl", "is-enabled", unit)
	if strings.TrimSpace(enabled) != "enabled" {
		return fmt.Errorf("служба %s не включена", unit)
	}
	return nil
}

func (s *Subsystem) remove(ctx context.Context, item ownedServer) error {
	if item.Type == "xray" {
		server := config.VPNServer{Index: item.Index, Type: "xray"}
		s.cleanupXray(ctx, server)
		unitName := item.Unit
		if unitName == "" {
			unitName = xrayUnitName(server)
		}
		if err := s.verifyUnitStopped(ctx, unitName); err != nil {
			return err
		}
		conf, unit := s.xrayPaths(server)
		if err := pathsAbsent(conf, unit); err != nil {
			return err
		}
		return nil
	}
	if item.Type == "ocserv" {
		server := config.VPNServer{Index: item.Index, Type: "ocserv"}
		s.cleanupOcserv(ctx, server)
		unitName := item.Unit
		if unitName == "" {
			unitName = ocservUnitName(server)
		}
		if err := s.verifyUnitStopped(ctx, unitName); err != nil {
			return err
		}
		if s.linkExists(InterfaceName(server)) {
			return fmt.Errorf("интерфейс %s остался в системе", InterfaceName(server))
		}
		paths := s.ocservPaths(server)
		if err := pathsAbsent(paths.conf, paths.passwd, paths.auth, paths.unit, paths.users, paths.tls); err != nil {
			return err
		}
		return nil
	}
	if item.Type == "ikev2" {
		if s.linkExists(item.Name) {
			_, _ = s.Runner.Run(ctx, "ip", "link", "delete", item.Name)
		}
		if s.linkExists(item.Name) {
			return fmt.Errorf("интерфейс %s остался в системе", item.Name)
		}
		return nil
	}
	if s.linkExists(item.Name) {
		_, _ = s.Runner.Run(ctx, "ip", "link", "delete", item.Name)
	}
	_ = os.Remove(filepath.Join(s.StateDir, item.Name+".conf"))
	if s.linkExists(item.Name) {
		return fmt.Errorf("интерфейс %s остался в системе", item.Name)
	}
	return pathsAbsent(filepath.Join(s.StateDir, item.Name+".conf"))
}

func (s *Subsystem) verifyUnitStopped(ctx context.Context, unit string) error {
	active, _ := s.Runner.Run(ctx, "systemctl", "is-active", unit)
	if strings.TrimSpace(active) == "active" {
		return fmt.Errorf("служба %s осталась активной", unit)
	}
	return nil
}

func pathsAbsent(paths ...string) error {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("артефакт %s остался в системе", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (s *Subsystem) linkExists(name string) bool {
	_, err := os.Stat(filepath.Join(s.SysClassNet, name))
	return err == nil
}

func (s *Subsystem) ownedPath() string { return filepath.Join(s.StateDir, "owned-vpn-servers.json") }

func (s *Subsystem) readOwned() ([]ownedServer, error) {
	data, err := os.ReadFile(s.ownedPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []ownedServer
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("разбор списка VPN-серверов: %w", err)
	}
	return out, nil
}

func (s *Subsystem) writeOwned(items []ownedServer) error {
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(s.ownedPath(), append(data, '\n'), 0o600)
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	_, err := system.WriteFileAtomicIfChanged(path, data, mode)
	return err
}

func PeerCIDR(peer config.VPNPeer) string {
	addr, err := netip.ParseAddr(peer.Address)
	if err != nil {
		return ""
	}
	return netip.PrefixFrom(addr, 32).String()
}
