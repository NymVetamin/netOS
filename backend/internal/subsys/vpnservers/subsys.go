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
	"sort"
	"strings"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type ownedServer struct {
	Name  string `json:"name"`
	Index int    `json:"index"`
}

type Subsystem struct {
	Runner      system.Runner
	StateDir    string
	SysClassNet string
	ProcSysNet  string
}

func New(r system.Runner, stateDir string) *Subsystem {
	return &Subsystem{Runner: r, StateDir: stateDir, SysClassNet: "/sys/class/net", ProcSysNet: "/proc/sys/net"}
}

func (s *Subsystem) Name() string { return "vpn-servers" }

func InterfaceName(server config.VPNServer) string { return fmt.Sprintf("wg-srv%d", server.Index) }

func enabledServers(cfg *config.Config) []config.VPNServer {
	var out []config.VPNServer
	for _, server := range cfg.VPNServers {
		if server.Enabled && server.Type == "wireguard" {
			out = append(out, server)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

func (s *Subsystem) Plan(old, next *config.Config) ([]apply.Action, error) {
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
		actions = append(actions, apply.Action{Kind: kind, Target: server.Name, Detail: InterfaceName(server), Disruptive: true})
	}
	for _, server := range previous {
		actions = append(actions, apply.Action{Kind: "delete", Target: server.Name, Detail: InterfaceName(server), Disruptive: true})
	}
	return actions, nil
}

func (s *Subsystem) Apply(ctx context.Context, cfg *config.Config) error {
	wanted := enabledServers(cfg)
	owned, err := s.readOwned()
	if err != nil {
		return err
	}
	wantedNames := map[string]bool{}
	ownedNames := map[string]bool{}
	for _, server := range wanted {
		wantedNames[InterfaceName(server)] = true
	}
	for _, item := range owned {
		ownedNames[item.Name] = true
		if !wantedNames[item.Name] {
			s.remove(ctx, item)
		}
	}
	var nextOwned []ownedServer
	var created []ownedServer
	for _, server := range wanted {
		item := ownedServer{Name: InterfaceName(server), Index: server.Index}
		createdNow, err := s.applyWireGuard(ctx, server, ownedNames[item.Name], cfg.IPv6.Mode == "off")
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
	if _, err := s.Runner.Run(ctx, "ip", "link", "set", "dev", name, "mtu", fmt.Sprint(mtu), "up"); err != nil {
		return fail(fmt.Errorf("поднятие интерфейса: %w", err))
	}
	if disableIPv6 {
		path := filepath.Join(s.ProcSysNet, "ipv6", "conf", name, "disable_ipv6")
		if err := os.WriteFile(path, []byte("1"), 0o644); err != nil && !os.IsNotExist(err) {
			return fail(fmt.Errorf("подавление IPv6 на %s: %w", name, err))
		}
	}
	return created, nil
}

func (s *Subsystem) ensureAddress(ctx context.Context, name, address string) error {
	out, _ := s.Runner.Run(ctx, "ip", "-o", "-4", "addr", "show", "dev", name)
	if strings.Contains(out, " inet "+address+" ") || strings.HasSuffix(strings.TrimSpace(out), " inet "+address) {
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

func (s *Subsystem) Health(ctx context.Context, cfg *config.Config) error {
	for _, server := range enabledServers(cfg) {
		name := InterfaceName(server)
		if !s.linkExists(name) {
			return fmt.Errorf("интерфейс %s отсутствует", name)
		}
		show, err := s.Runner.Run(ctx, "wg", "show", name, "listen-port")
		if err != nil || strings.TrimSpace(show) != fmt.Sprint(server.Port) {
			return fmt.Errorf("сервер %s не слушает UDP-порт %d", server.Name, server.Port)
		}
		addrs, err := s.Runner.Run(ctx, "ip", "-o", "-4", "addr", "show", "dev", name)
		if err != nil || !strings.Contains(addrs, server.Subnet) {
			return fmt.Errorf("на %s нет адреса %s", name, server.Subnet)
		}
	}
	return nil
}

func (s *Subsystem) remove(ctx context.Context, item ownedServer) {
	if s.linkExists(item.Name) {
		_, _ = s.Runner.Run(ctx, "ip", "link", "delete", item.Name)
	}
	_ = os.Remove(filepath.Join(s.StateDir, item.Name+".conf"))
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
	if system.FileChanged(path, data) {
		return system.WriteFileAtomic(path, data, mode)
	}
	return os.Chmod(path, mode)
}

func PeerCIDR(peer config.VPNPeer) string {
	addr, err := netip.ParseAddr(peer.Address)
	if err != nil {
		return ""
	}
	return netip.PrefixFrom(addr, 32).String()
}
