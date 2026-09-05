// Package channels поднимает исходящие VPN-каналы и их таблицы маршрутизации.
package channels

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	goruntime "runtime"
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

type channelFileSnapshot struct {
	path    string
	existed bool
	data    []byte
	mode    os.FileMode
}

type removedChannelSnapshot struct {
	owned     ownedChannel
	files     []channelFileSnapshot
	addresses string
	link      string
}

func captureChannelFiles(paths ...string) ([]channelFileSnapshot, error) {
	snapshots := make([]channelFileSnapshot, 0, len(paths))
	for _, path := range paths {
		snapshot := channelFileSnapshot{path: path}
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			snapshots = append(snapshots, snapshot)
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("артефакт канала %s не является обычным файлом", path)
		}
		snapshot.existed = true
		snapshot.mode = info.Mode().Perm()
		snapshot.data, err = os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

func restoreChannelFiles(snapshots []channelFileSnapshot) error {
	for _, snapshot := range snapshots {
		if !snapshot.existed {
			if err := os.Remove(snapshot.path); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		if err := system.WriteFileAtomic(snapshot.path, snapshot.data, snapshot.mode); err != nil {
			return err
		}
	}
	return nil
}

func (s *Subsystem) captureRemovedChannel(ctx context.Context, owned ownedChannel) (removedChannelSnapshot, error) {
	snapshot := removedChannelSnapshot{owned: owned}
	var paths []string
	switch owned.Type {
	case "openconnect":
		conf, password, script, unit := s.openConnectPaths(config.Channel{Index: owned.Index})
		paths = []string{conf, password, script, unit}
	case "xray":
		conf, unit := s.xrayPaths(config.Channel{Index: owned.Index})
		paths = []string{conf, unit}
	default:
		paths = []string{filepath.Join(s.StateDir, owned.Name+".conf")}
		snapshot.addresses, _ = s.Runner.Run(ctx, "ip", "-o", "-4", "addr", "show", "dev", owned.Name)
		snapshot.link, _ = s.Runner.Run(ctx, "ip", "-o", "link", "show", "dev", owned.Name)
	}
	var err error
	snapshot.files, err = captureChannelFiles(paths...)
	return snapshot, err
}

func (s *Subsystem) restoreRemovedChannels(snapshots []removedChannelSnapshot) error {
	ctx := context.Background()
	for i := len(snapshots) - 1; i >= 0; i-- {
		snapshot := snapshots[i]
		if err := restoreChannelFiles(snapshot.files); err != nil {
			return err
		}
		owned := snapshot.owned
		ch := config.Channel{Index: owned.Index, Type: owned.Type}
		switch owned.Type {
		case "openconnect", "xray":
			unit := owned.Unit
			if unit == "" && owned.Type == "openconnect" {
				unit = openConnectUnitName(ch)
			} else if unit == "" {
				unit = xrayUnitName(ch)
			}
			_, _ = s.Runner.Run(ctx, "systemctl", "daemon-reload")
			if err := s.ensureUnitEnabled(ctx, unit); err != nil {
				return err
			}
			if _, err := s.Runner.Run(ctx, "systemctl", "restart", unit); err != nil {
				return err
			}
			deadline := time.Now().Add(20 * time.Second)
			for !s.linkExists(owned.Name) && time.Now().Before(deadline) {
				time.Sleep(250 * time.Millisecond)
			}
			if !s.linkExists(owned.Name) {
				return fmt.Errorf("служба %s не восстановила интерфейс %s", unit, owned.Name)
			}
		default:
			if !s.linkExists(owned.Name) {
				if _, err := s.Runner.Run(ctx, "ip", "link", "add", "name", owned.Name, "type", "wireguard"); err != nil {
					return err
				}
			}
			conf := filepath.Join(s.StateDir, owned.Name+".conf")
			if _, err := s.Runner.Run(ctx, "wg", "syncconf", owned.Name, conf); err != nil {
				return err
			}
			addresses := inetAddresses(snapshot.addresses)
			if len(addresses) > 0 {
				_, _ = s.Runner.Run(ctx, "ip", "-4", "addr", "flush", "dev", owned.Name)
				for _, address := range addresses {
					_, _ = s.Runner.Run(ctx, "ip", "-4", "addr", "add", address, "dev", owned.Name)
				}
			}
			if mtu := linkMTU(snapshot.link); mtu != "" {
				_, _ = s.Runner.Run(ctx, "ip", "link", "set", "dev", owned.Name, "mtu", mtu, "up")
			}
		}
		if err := s.ensureRoutes(ctx, ch, owned.Name); err != nil {
			return err
		}
		if err := s.ensureRule(ctx, ch); err != nil {
			return err
		}
	}
	return nil
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
	case "openconnect", "xray":
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
		if ch.Enabled && (ch.Type == "wireguard" || ch.Type == "openconnect" || ch.Type == "xray") {
			out = append(out, ch)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

func (s *Subsystem) Plan(old, new *config.Config) ([]apply.Action, error) {
	return s.PlanContext(context.Background(), old, new)
}

func (s *Subsystem) PlanContext(ctx context.Context, old, new *config.Config) ([]apply.Action, error) {
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
	if len(actions) == 0 {
		if err := s.Health(ctx, new); err != nil {
			actions = append(actions, apply.Action{Kind: "update", Target: "channels", Detail: err.Error(), Disruptive: true})
		}
	}
	return actions, nil
}

func (s *Subsystem) Apply(ctx context.Context, cfg *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	wanted := enabledChannels(cfg)
	if err := preflightChannels(wanted); err != nil {
		return err
	}
	owned, err := s.readOwned()
	if err != nil {
		return err
	}
	tableSnapshot, err := captureChannelFiles(s.RTTablesPath)
	if err != nil {
		return err
	}
	wantedOwned := map[string]ownedChannel{}
	for _, ch := range wanted {
		name := InterfaceName(ch)
		unit := ""
		if ch.Type == "openconnect" {
			unit = openConnectUnitName(ch)
		} else if ch.Type == "xray" {
			unit = xrayUnitName(ch)
		}
		wantedOwned[name] = ownedChannel{Name: name, Index: ch.Index, Type: ch.Type, Unit: unit}
	}
	retained := map[string]bool{}
	var removed []removedChannelSnapshot
	rollbackRemoved := func(cause error) error {
		var rollbackErrors []string
		if err := restoreChannelFiles(tableSnapshot); err != nil {
			rollbackErrors = append(rollbackErrors, "каталог таблиц: "+err.Error())
		}
		if len(removed) > 0 {
			if err := s.restoreRemovedChannels(removed); err != nil {
				rollbackErrors = append(rollbackErrors, "ранее удалённые каналы: "+err.Error())
			}
		}
		if len(rollbackErrors) > 0 {
			return fmt.Errorf("%v; восстановление Apply: %s", cause, strings.Join(rollbackErrors, "; "))
		}
		return cause
	}
	for _, previous := range owned {
		expected, exists := wantedOwned[previous.Name]
		if exists && previous.Type == expected.Type && previous.Unit == expected.Unit {
			retained[previous.Name] = true
			continue
		}
		snapshot, err := s.captureRemovedChannel(ctx, previous)
		if err != nil {
			return rollbackRemoved(err)
		}
		removed = append(removed, snapshot)
		if err := s.removeChannel(ctx, previous); err != nil {
			return rollbackRemoved(fmt.Errorf("удаление старого канала %s: %w", previous.Name, err))
		}
	}

	if err := s.writeTables(wanted); err != nil {
		return rollbackRemoved(err)
	}
	var nextOwned []ownedChannel
	var created []ownedChannel
	for _, ch := range wanted {
		name := InterfaceName(ch)
		var createdNow bool
		var unit string
		switch ch.Type {
		case "wireguard":
			createdNow, err = s.applyWireGuard(ctx, ch, retained[name], cfg.IPv6.Mode == "off")
		case "openconnect":
			unit = openConnectUnitName(ch)
			createdNow, err = s.applyOpenConnect(ctx, ch, retained[name], cfg.IPv6.Mode == "off")
		case "xray":
			unit = xrayUnitName(ch)
			createdNow, err = s.applyXray(ctx, ch, retained[name], cfg.IPv6.Mode == "off")
		}
		if err != nil {
			for _, provisional := range created {
				_ = s.removeChannel(ctx, provisional)
			}
			return rollbackRemoved(fmt.Errorf("канал %s: %w", ch.Name, err))
		}
		if createdNow {
			created = append(created, ownedChannel{Name: name, Index: ch.Index, Type: ch.Type, Unit: unit})
		}
		nextOwned = append(nextOwned, ownedChannel{Name: name, Index: ch.Index, Type: ch.Type, Unit: unit})
	}
	if err := s.writeOwned(nextOwned); err != nil {
		for _, provisional := range created {
			_ = s.removeChannel(ctx, provisional)
		}
		return rollbackRemoved(err)
	}
	s.states = map[string]*channelState{}
	s.pausedUntil = time.Now().Add(15 * time.Second)
	return nil
}

func preflightChannels(channels []config.Channel) error {
	for _, ch := range channels {
		var err error
		switch ch.Type {
		case "wireguard":
			_, err = RenderWireGuard(ch)
		case "openconnect":
			_, err = ch.OpenConnectConfig()
		case "xray":
			_, err = RenderXray(ch)
		}
		if err != nil {
			return fmt.Errorf("канал %s: %w", ch.Name, err)
		}
	}
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
	// Пустое значение пишем явно нулевым ключом, а не пропуском строки:
	// wg syncconf меняет только то, что в файле названо, а отсутствующий
	// параметр оставляет в ядре как есть. Очищенный в панели ключ продолжал
	// действовать на живом интерфейсе.
	fmt.Fprintf(&b, "PresharedKey = %s\n", presharedKeyOrZero(wg.PresharedKey))
	fmt.Fprintf(&b, "Endpoint = %s\n", wg.Endpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(wg.AllowedIPs, ", "))
	// Ноль означает «периодических пакетов нет», и сказать это надо вслух: без
	// строки прежнее значение keepalive оставалось в ядре навсегда.
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", max(wg.PersistentKeepalive, 0))
	return b.String(), nil
}

// zeroWireGuardKey — 32 нулевых байта в base64. Для WireGuard такой общий ключ
// равнозначен его отсутствию, и это единственный способ снять уже заданный:
// строки «PresharedKey =» без значения формат не допускает.
const zeroWireGuardKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func presharedKeyOrZero(key string) string {
	if key == "" {
		return zeroWireGuardKey
	}
	return key
}

func (s *Subsystem) applyWireGuard(ctx context.Context, ch config.Channel, wasOwned, disableIPv6 bool) (created bool, retErr error) {
	name := InterfaceName(ch)
	existedBefore := s.linkExists(InterfaceName(ch))
	confPath := filepath.Join(s.StateDir, name+".conf")
	snapshots, err := captureChannelFiles(confPath)
	if err != nil {
		return false, err
	}
	oldAddresses, _ := s.Runner.Run(ctx, "ip", "-o", "-4", "addr", "show", "dev", name)
	oldLink, _ := s.Runner.Run(ctx, "ip", "-o", "link", "show", "dev", name)
	retErr = s.applyWireGuardInner(ctx, ch, wasOwned, disableIPv6)
	created = !existedBefore && s.linkExists(name)
	if retErr == nil {
		return created, nil
	}
	rollbackCtx := context.Background()
	if !wasOwned {
		if !existedBefore {
			_ = s.removeChannel(rollbackCtx, ownedChannel{Name: name, Index: ch.Index})
			_ = os.Remove(confPath)
		}
		return false, retErr
	}
	if err := restoreChannelFiles(snapshots); err != nil {
		return false, fmt.Errorf("%v; rollback WireGuard: %w", retErr, err)
	}
	if !s.linkExists(name) {
		if _, err := s.Runner.Run(rollbackCtx, "ip", "link", "add", "name", name, "type", "wireguard"); err != nil {
			return false, fmt.Errorf("%v; rollback WireGuard interface: %w", retErr, err)
		}
	}
	if len(snapshots) > 0 && snapshots[0].existed {
		if _, err := s.Runner.Run(rollbackCtx, "wg", "syncconf", name, confPath); err != nil {
			return false, fmt.Errorf("%v; rollback WireGuard config: %w", retErr, err)
		}
	}
	addresses := inetAddresses(oldAddresses)
	if len(addresses) > 0 {
		_, _ = s.Runner.Run(rollbackCtx, "ip", "-4", "addr", "flush", "dev", name)
		for _, address := range addresses {
			_, _ = s.Runner.Run(rollbackCtx, "ip", "-4", "addr", "add", address, "dev", name)
		}
	}
	if mtu := linkMTU(oldLink); mtu != "" {
		_, _ = s.Runner.Run(rollbackCtx, "ip", "link", "set", "dev", name, "mtu", mtu, "up")
	}
	_ = s.ensureRoutes(rollbackCtx, ch, name)
	_ = s.ensureRule(rollbackCtx, ch)
	return false, retErr
}

func inetAddresses(output string) []string {
	var addresses []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "inet" {
				addresses = append(addresses, fields[i+1])
			}
		}
	}
	return addresses
}

func linkMTU(output string) string {
	fields := strings.Fields(output)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "mtu" {
			return fields[i+1]
		}
	}
	return ""
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
	if !hasDefaultRoute(out, name) {
		if _, err := s.Runner.Run(ctx, "ip", "-4", "route", "replace", "default", "dev", name,
			"metric", "100", "table", table, "proto", fmt.Sprint(config.RouteProto)); err != nil {
			return fmt.Errorf("маршрут канала: %w", err)
		}
	}
	if !hasBlackholeDefault(out) {
		if _, err := s.Runner.Run(ctx, "ip", "-4", "route", "replace", "blackhole", "default",
			"metric", "1000", "table", table, "proto", fmt.Sprint(config.RouteProto)); err != nil {
			return fmt.Errorf("kill-switch канала: %w", err)
		}
	}
	return nil
}

func hasDefaultRoute(out, name string) bool {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "default" {
			continue
		}
		for i := 1; i+1 < len(fields); i++ {
			if fields[i] == "dev" && fields[i+1] == name {
				return true
			}
		}
	}
	return false
}

func hasBlackholeDefault(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "blackhole" && fields[1] == "default" {
			return true
		}
	}
	return false
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
		if hasChannelRuleLine(line, priority, mark, table, tableName) {
			return nil
		}
	}
	if hasRulePriority(out, priority) {
		if _, err := s.Runner.Run(ctx, "ip", "-4", "rule", "del", "priority", priority); err != nil {
			return fmt.Errorf("удаление старого правила канала: %w", err)
		}
	}
	if _, err := s.Runner.Run(ctx, "ip", "-4", "rule", "add", "fwmark", mark,
		"priority", priority, "lookup", table); err != nil {
		return fmt.Errorf("правило канала: %w", err)
	}
	return nil
}

func hasRulePriority(out, priority string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), priority+":") {
			return true
		}
	}
	return false
}

func hasChannelRuleLine(line, priority, mark, table, tableName string) bool {
	if !strings.HasPrefix(strings.TrimSpace(line), priority+":") {
		return false
	}
	fields := strings.Fields(line)
	foundMark, foundTable := false, false
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "fwmark":
			foundMark = fields[i+1] == mark
		case "lookup", "table":
			foundTable = fields[i+1] == table || fields[i+1] == tableName
		}
	}
	return foundMark && foundTable
}

func (s *Subsystem) suppressIPv6(name string) error {
	path := filepath.Join(s.ProcSysNet, "ipv6", "conf", name, "disable_ipv6")
	if err := os.WriteFile(path, []byte("1"), 0o644); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("подавление IPv6 на %s: %w", name, err)
	}
	return nil
}

func (s *Subsystem) Health(ctx context.Context, cfg *config.Config) error {
	channels := enabledChannels(cfg)
	var expectedOwned []ownedChannel
	for _, ch := range channels {
		unit := ""
		if ch.Type == "openconnect" {
			unit = openConnectUnitName(ch)
		} else if ch.Type == "xray" {
			unit = xrayUnitName(ch)
		}
		expectedOwned = append(expectedOwned, ownedChannel{Name: InterfaceName(ch), Index: ch.Index, Type: ch.Type, Unit: unit})
	}
	owned, err := s.readOwned()
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(owned, expectedOwned) {
		return fmt.Errorf("список owned-каналов расходится с конфигурацией")
	}
	if err := healthyChannelFile(s.RTTablesPath, renderTables(channels), 0o644); err != nil {
		return err
	}
	if len(channels) == 0 {
		return nil
	}
	rules, err := s.Runner.Run(ctx, "ip", "-4", "rule", "show")
	if err != nil {
		return err
	}
	for _, ch := range channels {
		name := InterfaceName(ch)
		if !s.linkExists(name) {
			return fmt.Errorf("интерфейс %s отсутствует", name)
		}
		if ch.Type == "wireguard" {
			if _, err := s.Runner.Run(ctx, "wg", "show", name); err != nil {
				return fmt.Errorf("интерфейс %s не принят WireGuard: %w", name, err)
			}
			wg, err := ch.WireGuardConfig()
			if err != nil {
				return err
			}
			addrs, err := s.Runner.Run(ctx, "ip", "-o", "-4", "addr", "show", "dev", name)
			if err != nil || !hasExactAddress(addrs, wg.Address) {
				return fmt.Errorf("на %s нет адреса %s", name, wg.Address)
			}
			conf, err := RenderWireGuard(ch)
			if err != nil {
				return err
			}
			if err := healthyChannelFile(filepath.Join(s.StateDir, name+".conf"), []byte(conf), 0o600); err != nil {
				return err
			}
		} else if ch.Type == "openconnect" || ch.Type == "xray" {
			unit := openConnectUnitName(ch)
			if ch.Type == "xray" {
				unit = xrayUnitName(ch)
			}
			if err := s.unitActiveEnabled(ctx, unit); err != nil {
				return fmt.Errorf("служба канала %s: %w", ch.Name, err)
			}
			if ch.Type == "openconnect" {
				oc, err := ch.OpenConnectConfig()
				if err != nil {
					return err
				}
				conf, password, script, unitPath := s.openConnectPaths(ch)
				files := []struct {
					path string
					data []byte
					mode os.FileMode
				}{
					{conf, []byte(renderOpenConnect(ch, oc, script, cfg.IPv6.Mode == "off")), 0o600},
					{password, []byte(oc.Password + "\n"), 0o600},
					{script, []byte(renderOpenConnectScript(oc.MTU)), 0o700},
					{unitPath, []byte(renderOpenConnectUnit(ch, conf, password)), 0o644},
				}
				for _, file := range files {
					if err := healthyChannelFile(file.path, file.data, file.mode); err != nil {
						return err
					}
				}
			} else {
				conf, unitPath := s.xrayPaths(ch)
				data, err := RenderXray(ch)
				if err != nil {
					return err
				}
				if err := healthyChannelFile(conf, data, 0o600); err != nil {
					return err
				}
				if err := healthyChannelFile(unitPath, []byte(renderXrayUnit(ch, conf)), 0o644); err != nil {
					return err
				}
			}
		}
		routes, err := s.Runner.Run(ctx, "ip", "-4", "route", "show", "table", fmt.Sprint(TableNumber(ch)))
		if err != nil || !hasDefaultRoute(routes, name) || !hasBlackholeDefault(routes) {
			return fmt.Errorf("таблица канала %s неполна", ch.Name)
		}
		priority := fmt.Sprint(Priority(ch))
		mark := fmt.Sprintf("0x%x", Mark(ch))
		table := fmt.Sprint(TableNumber(ch))
		tableName := "netos-ch" + fmt.Sprint(ch.Index)
		found := false
		for _, line := range strings.Split(rules, "\n") {
			if hasChannelRuleLine(line, priority, mark, table, tableName) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("правило fwmark канала %s отсутствует", ch.Name)
		}
	}
	return nil
}

func hasExactAddress(output, address string) bool {
	count := 0
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "inet" && fields[i+1] == address {
				count++
			}
		}
	}
	return count == 1
}

func healthyChannelFile(path string, expected []byte, mode os.FileMode) error {
	if system.FileChanged(path, expected) {
		return fmt.Errorf("артефакт канала %s расходится с конфигурацией", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if goruntime.GOOS != "windows" && info.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("права артефакта канала %s: %04o, ожидалось %04o", path, info.Mode().Perm(), mode.Perm())
	}
	return nil
}

func (s *Subsystem) unitActiveEnabled(ctx context.Context, unit string) error {
	active, _ := s.Runner.Run(ctx, "systemctl", "is-active", unit)
	if strings.TrimSpace(active) != "active" {
		return fmt.Errorf("%s не активна", unit)
	}
	enabled, _ := s.Runner.Run(ctx, "systemctl", "is-enabled", unit)
	if strings.TrimSpace(enabled) != "enabled" {
		return fmt.Errorf("%s не включена", unit)
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

func (s *Subsystem) linkExists(name string) bool {
	_, err := os.Stat(filepath.Join(s.SysClassNet, name))
	return err == nil
}

func (s *Subsystem) writeTables(channels []config.Channel) error {
	return writeFileIfChanged(s.RTTablesPath, renderTables(channels), 0o644)
}

func renderTables(channels []config.Channel) []byte {
	var b strings.Builder
	b.WriteString("# Сгенерировано netOS. Правки будут перезаписаны.\n")
	for _, ch := range channels {
		fmt.Fprintf(&b, "%d\tnetos-ch%d\n", TableNumber(ch), ch.Index)
	}
	return []byte(b.String())
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

func (s *Subsystem) removeChannel(ctx context.Context, ch ownedChannel) error {
	if ch.Unit != "" && ch.Type != "openconnect" && ch.Type != "xray" {
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
	if ch.Type == "xray" {
		placeholder := config.Channel{Index: ch.Index, Type: "xray"}
		s.cleanupXray(ctx, placeholder)
	}
	if ch.Unit != "" {
		active, _ := s.Runner.Run(ctx, "systemctl", "is-active", ch.Unit)
		if strings.TrimSpace(active) == "active" {
			return fmt.Errorf("служба %s осталась активной", ch.Unit)
		}
	}
	if s.linkExists(ch.Name) {
		return fmt.Errorf("интерфейс %s остался в системе", ch.Name)
	}
	rules, err := s.Runner.Run(ctx, "ip", "-4", "rule", "show")
	if err != nil {
		return fmt.Errorf("проверка удаления правила: %w", err)
	}
	if hasRulePriority(rules, fmt.Sprint(priorityBase+ch.Index)) {
		return fmt.Errorf("правило канала с приоритетом %d осталось", priorityBase+ch.Index)
	}
	routes, err := s.Runner.Run(ctx, "ip", "-4", "route", "show", "table", fmt.Sprint(tableBase+ch.Index))
	if err != nil {
		return fmt.Errorf("проверка очистки таблицы: %w", err)
	}
	if strings.TrimSpace(routes) != "" {
		return fmt.Errorf("таблица %d не очищена", tableBase+ch.Index)
	}
	return nil
}
