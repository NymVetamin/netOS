// Package channels поднимает исходящие VPN-каналы и их таблицы маршрутизации.
package channels

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

const (
	tableBase    = 1000
	markBase     = 0x1000
	priorityBase = 10000
)

type ownedChannel struct {
	Name  string `json:"name"`
	Index int    `json:"index"`
	Type  string `json:"type,omitempty"`
	Unit  string `json:"unit,omitempty"`
}

type Subsystem struct {
	Runner       system.Runner
	StateDir     string
	RTTablesPath string
	SysClassNet  string
	ProcSysNet   string
	UnitDir      string
	Logger       Logger
	Probe        func(context.Context, config.Channel, string) bool

	mu          sync.Mutex
	states      map[string]*channelState
	pausedUntil time.Time
}

type Logger interface {
	Infof(string, ...any)
	Warnf(string, ...any)
}

func New(r system.Runner, stateDir string, loggers ...Logger) *Subsystem {
	s := &Subsystem{
		Runner:       r,
		StateDir:     stateDir,
		RTTablesPath: "/etc/iproute2/rt_tables.d/netos-channels.conf",
		SysClassNet:  "/sys/class/net",
		ProcSysNet:   "/proc/sys/net",
		UnitDir:      "/etc/systemd/system",
		states:       map[string]*channelState{},
	}
	if len(loggers) > 0 {
		s.Logger = loggers[0]
	}
	s.Probe = s.probe
	return s
}

func (s *Subsystem) Name() string { return "channels" }

func InterfaceName(ch config.Channel) string {
	switch ch.Type {
	case "wireguard":
		return fmt.Sprintf("wg-ch%d", ch.Index)
	case "openconnect":
		return fmt.Sprintf("tun-ch%d", ch.Index)
	}
	return fmt.Sprintf("ch%d", ch.Index)
}
func TableNumber(ch config.Channel) int { return tableBase + ch.Index }
func Mark(ch config.Channel) int        { return markBase + ch.Index }
func Priority(ch config.Channel) int    { return priorityBase + ch.Index }

func enabledChannels(cfg *config.Config) []config.Channel {
	var out []config.Channel
	for _, ch := range cfg.Channels {
		if ch.Enabled && (ch.Type == "wireguard" || ch.Type == "openconnect") {
			out = append(out, ch)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

func (s *Subsystem) Plan(old, new *config.Config) ([]apply.Action, error) {
	wanted := enabledChannels(new)
	if old == nil {
		var actions []apply.Action
		for _, ch := range wanted {
			actions = append(actions, apply.Action{
				Kind: "create", Target: ch.Name, Detail: InterfaceName(ch), Disruptive: true,
			})
		}
		return actions, nil
	}
	previous := map[string]config.Channel{}
	for _, ch := range enabledChannels(old) {
		previous[ch.ID] = ch
	}
	var actions []apply.Action
	for _, ch := range wanted {
		before, ok := previous[ch.ID]
		delete(previous, ch.ID)
		if !ok {
			actions = append(actions, apply.Action{Kind: "create", Target: ch.Name, Detail: InterfaceName(ch), Disruptive: true})
		} else if !reflect.DeepEqual(before, ch) {
			actions = append(actions, apply.Action{Kind: "update", Target: ch.Name, Detail: InterfaceName(ch), Disruptive: true})
		}
	}
	for _, ch := range previous {
		actions = append(actions, apply.Action{Kind: "delete", Target: ch.Name, Detail: InterfaceName(ch), Disruptive: true})
	}
	return actions, nil
}

func (s *Subsystem) Apply(ctx context.Context, cfg *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	wanted := enabledChannels(cfg)
	owned, err := s.readOwned()
	if err != nil {
		return err
	}
	wantedNames := map[string]bool{}
	for _, ch := range wanted {
		wantedNames[InterfaceName(ch)] = true
	}
	for _, previous := range owned {
		if wantedNames[previous.Name] {
			continue
		}
		s.removeChannel(ctx, previous)
	}

	if err := s.writeTables(wanted); err != nil {
		return err
	}
	ownedNames := map[string]bool{}
	for _, previous := range owned {
		ownedNames[previous.Name] = true
	}
	var nextOwned []ownedChannel
	var created []ownedChannel
	for _, ch := range wanted {
		name := InterfaceName(ch)
		var createdNow bool
		var unit string
		switch ch.Type {
		case "wireguard":
			createdNow, err = s.applyWireGuard(ctx, ch, ownedNames[name], cfg.IPv6.Mode == "off")
		case "openconnect":
			unit = openConnectUnitName(ch)
			createdNow, err = s.applyOpenConnect(ctx, ch, cfg.IPv6.Mode == "off")
		}
		if err != nil {
			for _, provisional := range created {
				s.removeChannel(ctx, provisional)
			}
			return fmt.Errorf("канал %s: %w", ch.Name, err)
		}
		if createdNow {
			created = append(created, ownedChannel{Name: name, Index: ch.Index, Type: ch.Type, Unit: unit})
		}
		nextOwned = append(nextOwned, ownedChannel{Name: name, Index: ch.Index, Type: ch.Type, Unit: unit})
	}
	if err := s.writeOwned(nextOwned); err != nil {
		for _, provisional := range created {
			s.removeChannel(ctx, provisional)
		}
		return err
	}
	s.states = map[string]*channelState{}
	s.pausedUntil = time.Now().Add(15 * time.Second)
	return nil
}

func RenderWireGuard(ch config.Channel) (string, error) {
	wg, err := ch.WireGuardConfig()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintln(&b, "# Сгенерировано netOS. Файл содержит секреты; права 0600.")
	fmt.Fprintln(&b, "[Interface]")
	fmt.Fprintf(&b, "PrivateKey = %s\n", wg.PrivateKey)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "[Peer]")
	fmt.Fprintf(&b, "PublicKey = %s\n", wg.PeerPublicKey)
	if wg.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", wg.PresharedKey)
	}
	fmt.Fprintf(&b, "Endpoint = %s\n", wg.Endpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(wg.AllowedIPs, ", "))
	if wg.PersistentKeepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", wg.PersistentKeepalive)
	}
	return b.String(), nil
}

func (s *Subsystem) applyWireGuard(ctx context.Context, ch config.Channel, wasOwned, disableIPv6 bool) (bool, error) {
	existedBefore := s.linkExists(InterfaceName(ch))
	err := s.applyWireGuardInner(ctx, ch, wasOwned, disableIPv6)
	created := !existedBefore && s.linkExists(InterfaceName(ch))
	if err != nil && created {
		s.removeChannel(ctx, ownedChannel{Name: InterfaceName(ch), Index: ch.Index})
		created = false
	}
	return created, err
}

func (s *Subsystem) applyWireGuardInner(ctx context.Context, ch config.Channel, wasOwned, disableIPv6 bool) error {
	name := InterfaceName(ch)
	wg, err := ch.WireGuardConfig()
	if err != nil {
		return err
	}
	conf, err := RenderWireGuard(ch)
	if err != nil {
		return err
	}
	exists := s.linkExists(name)
	if exists && !wasOwned {
		return fmt.Errorf("интерфейс %s уже существует и не принадлежит netOS", name)
	}
	if exists {
		if _, err := s.Runner.Run(ctx, "wg", "show", name); err != nil {
			if _, delErr := s.Runner.Run(ctx, "ip", "link", "delete", name); delErr != nil {
				return fmt.Errorf("чужой тип интерфейса %s: %w", name, delErr)
			}
			exists = false
		}
	}
	confPath := filepath.Join(s.StateDir, name+".conf")
	if err := writeFileIfChanged(confPath, []byte(conf), 0o600); err != nil {
		return fmt.Errorf("сохранение конфигурации: %w", err)
	}
	if !exists {
		if _, err := s.Runner.Run(ctx, "ip", "link", "add", "name", name, "type", "wireguard"); err != nil {
			return fmt.Errorf("создание интерфейса: %w", err)
		}
	}
	if _, err := s.Runner.Run(ctx, "wg", "syncconf", name, confPath); err != nil {
		return fmt.Errorf("настройка WireGuard: %w", err)
	}
	if err := s.ensureAddress(ctx, name, wg.Address); err != nil {
		return err
	}
	mtu := wg.MTU
	if mtu == 0 {
		mtu = 1420
	}
	if _, err := s.Runner.Run(ctx, "ip", "link", "set", "dev", name, "mtu", fmt.Sprint(mtu), "up"); err != nil {
		return fmt.Errorf("поднятие интерфейса: %w", err)
	}
	if disableIPv6 {
		if err := s.suppressIPv6(name); err != nil {
			return err
		}
	}
	if err := s.ensureRoutes(ctx, ch, name); err != nil {
		return err
	}
	return s.ensureRule(ctx, ch)
}

func (s *Subsystem) ensureAddress(ctx context.Context, name, address string) error {
	out, _ := s.Runner.Run(ctx, "ip", "-o", "-4", "addr", "show", "dev", name)
	fields := strings.Fields(out)
	count := 0
	for _, field := range fields {
		if field == address {
			count++
		}
	}
	if count == 1 && strings.Count(out, " inet ") == 1 {
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

func (s *Subsystem) ensureRoutes(ctx context.Context, ch config.Channel, name string) error {
	table := fmt.Sprint(TableNumber(ch))
	out, _ := s.Runner.Run(ctx, "ip", "-4", "route", "show", "table", table)
	wantDefault := "default dev " + name
	if !strings.Contains(out, wantDefault) {
		if _, err := s.Runner.Run(ctx, "ip", "-4", "route", "replace", "default", "dev", name,
			"metric", "100", "table", table, "proto", fmt.Sprint(config.RouteProto)); err != nil {
			return fmt.Errorf("маршрут канала: %w", err)
		}
	}
	if !strings.Contains(out, "blackhole default") {
		if _, err := s.Runner.Run(ctx, "ip", "-4", "route", "replace", "blackhole", "default",
			"metric", "1000", "table", table, "proto", fmt.Sprint(config.RouteProto)); err != nil {
			return fmt.Errorf("kill-switch канала: %w", err)
		}
	}
	return nil
}

func (s *Subsystem) ensureRule(ctx context.Context, ch config.Channel) error {
	return s.ensureRuleTable(ctx, ch, TableNumber(ch))
}

func (s *Subsystem) ensureRuleTable(ctx context.Context, ch config.Channel, lookup int) error {
	priority := fmt.Sprint(Priority(ch))
	table := fmt.Sprint(lookup)
	mark := fmt.Sprintf("0x%x", Mark(ch))
	tableName := "netos-ch" + fmt.Sprint(lookup-tableBase)
	out, err := s.Runner.Run(ctx, "ip", "-4", "rule", "show")
	if err != nil {
		return fmt.Errorf("чтение правил: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), priority+":") &&
			strings.Contains(line, "fwmark "+mark) &&
			(strings.Contains(line, "lookup "+table) || strings.Contains(line, "lookup "+tableName)) {
			return nil
		}
	}
	_, _ = s.Runner.Run(ctx, "ip", "-4", "rule", "del", "priority", priority)
	if _, err := s.Runner.Run(ctx, "ip", "-4", "rule", "add", "fwmark", mark,
		"priority", priority, "lookup", table); err != nil {
		return fmt.Errorf("правило канала: %w", err)
	}
	return nil
}

func (s *Subsystem) suppressIPv6(name string) error {
	path := filepath.Join(s.ProcSysNet, "ipv6", "conf", name, "disable_ipv6")
	if err := os.WriteFile(path, []byte("1"), 0o644); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("подавление IPv6 на %s: %w", name, err)
	}
	return nil
}

func (s *Subsystem) Health(ctx context.Context, cfg *config.Config) error {
	rules, err := s.Runner.Run(ctx, "ip", "-4", "rule", "show")
	if err != nil {
		return err
	}
	for _, ch := range enabledChannels(cfg) {
		name := InterfaceName(ch)
		if !s.linkExists(name) {
			return fmt.Errorf("интерфейс %s отсутствует", name)
		}
		if ch.Type == "wireguard" {
			if _, err := s.Runner.Run(ctx, "wg", "show", name); err != nil {
				return fmt.Errorf("интерфейс %s не принят WireGuard: %w", name, err)
			}
			wg, _ := ch.WireGuardConfig()
			addrs, err := s.Runner.Run(ctx, "ip", "-o", "-4", "addr", "show", "dev", name)
			if err != nil || !strings.Contains(addrs, wg.Address) {
				return fmt.Errorf("на %s нет адреса %s", name, wg.Address)
			}
		} else if ch.Type == "openconnect" {
			active, _ := s.Runner.Run(ctx, "systemctl", "is-active", openConnectUnitName(ch))
			if strings.TrimSpace(active) != "active" {
				return fmt.Errorf("служба канала %s не работает", ch.Name)
			}
		}
		routes, err := s.Runner.Run(ctx, "ip", "-4", "route", "show", "table", fmt.Sprint(TableNumber(ch)))
		if err != nil || !strings.Contains(routes, "default dev "+name) || !strings.Contains(routes, "blackhole default") {
			return fmt.Errorf("таблица канала %s неполна", ch.Name)
		}
		if !strings.Contains(rules, fmt.Sprintf("%d:", Priority(ch))) ||
			!strings.Contains(rules, fmt.Sprintf("fwmark 0x%x", Mark(ch))) {
			return fmt.Errorf("правило fwmark канала %s отсутствует", ch.Name)
		}
	}
	return nil
}

func (s *Subsystem) linkExists(name string) bool {
	_, err := os.Stat(filepath.Join(s.SysClassNet, name))
	return err == nil
}

func (s *Subsystem) writeTables(channels []config.Channel) error {
	var b strings.Builder
	b.WriteString("# Сгенерировано netOS. Правки будут перезаписаны.\n")
	for _, ch := range channels {
		fmt.Fprintf(&b, "%d\tnetos-ch%d\n", TableNumber(ch), ch.Index)
	}
	return writeFileIfChanged(s.RTTablesPath, []byte(b.String()), 0o644)
}

func (s *Subsystem) ownedPath() string { return filepath.Join(s.StateDir, "owned-channels.json") }

func (s *Subsystem) readOwned() ([]ownedChannel, error) {
	data, err := os.ReadFile(s.ownedPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("чтение списка каналов: %w", err)
	}
	var owned []ownedChannel
	if err := json.Unmarshal(data, &owned); err != nil {
		return nil, fmt.Errorf("разбор списка каналов: %w", err)
	}
	return owned, nil
}

func (s *Subsystem) writeOwned(owned []ownedChannel) error {
	data, err := json.MarshalIndent(owned, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFileIfChanged(s.ownedPath(), data, 0o600)
}

func writeFileIfChanged(path string, data []byte, perm os.FileMode) error {
	if system.FileChanged(path, data) {
		return system.WriteFileAtomic(path, data, perm)
	}
	// Секретный файл мог быть создан старой версией с более широкими правами.
	return os.Chmod(path, perm)
}

func (s *Subsystem) removeChannel(ctx context.Context, ch ownedChannel) {
	if ch.Unit != "" && ch.Type != "openconnect" {
		_, _ = s.Runner.Run(ctx, "systemctl", "disable", ch.Unit)
		_, _ = s.Runner.Run(ctx, "systemctl", "stop", ch.Unit)
	}
	_, _ = s.Runner.Run(ctx, "ip", "-4", "rule", "del", "priority", fmt.Sprint(priorityBase+ch.Index))
	_, _ = s.Runner.Run(ctx, "ip", "-4", "route", "flush", "table", fmt.Sprint(tableBase+ch.Index))
	if s.linkExists(ch.Name) {
		_, _ = s.Runner.Run(ctx, "ip", "link", "delete", ch.Name)
	}
	_ = os.Remove(filepath.Join(s.StateDir, ch.Name+".conf"))
	if ch.Type == "openconnect" {
		placeholder := config.Channel{Index: ch.Index, Type: "openconnect"}
		s.cleanupOpenConnect(ctx, placeholder)
	}
}
