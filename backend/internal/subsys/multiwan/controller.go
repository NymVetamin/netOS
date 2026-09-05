// Package multiwan контролирует доступность нескольких аплинков и убирает
// маршрут отказавшего подключения до его восстановления.
package multiwan

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
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

type Logger interface {
	Infof(string, ...any)
	Warnf(string, ...any)
}

type discardLogger struct{}

func (discardLogger) Infof(string, ...any) {}
func (discardLogger) Warnf(string, ...any) {}

type linkState struct {
	Failures  int
	Successes int
	Down      bool
	Next      time.Time
}

type Controller struct {
	Runner    system.Runner
	StatePath string
	Logger    Logger
	Probe     func(context.Context, config.WAN, string) bool

	mu           sync.Mutex
	states       map[string]*linkState
	suppressed   map[string]string
	pausedUntil  time.Time
	balanceDirty bool
}

const (
	tableBase    = 3000
	markBase     = 0x3000
	priorityBase = 30000
)

func Table(w config.WAN) int    { return tableBase + w.Index }
func Mark(w config.WAN) int     { return markBase + w.Index }
func Priority(w config.WAN) int { return priorityBase + w.Index }

func New(r system.Runner, stateDir string, logger Logger) *Controller {
	if logger == nil {
		logger = discardLogger{}
	}
	c := &Controller{Runner: r, StatePath: filepath.Join(stateDir, "multiwan-suppressed.json"), Logger: logger}
	c.Probe = c.probe
	return c
}

func (c *Controller) Name() string { return "multiwan" }

func (c *Controller) Plan(old, next *config.Config) ([]apply.Action, error) {
	return c.PlanContext(context.Background(), old, next)
}

func (c *Controller) PlanContext(ctx context.Context, old, next *config.Config) ([]apply.Action, error) {
	if old == nil || !reflect.DeepEqual(old.MultiWAN, next.MultiWAN) || !reflect.DeepEqual(old.WANs, next.WANs) {
		if next.MultiWAN.Enabled {
			return []apply.Action{{Kind: "update", Target: "Multi-WAN failover", Detail: "пробы доступности", Disruptive: true}}, nil
		}
		if old != nil && old.MultiWAN.Enabled {
			return []apply.Action{{Kind: "delete", Target: "Multi-WAN failover", Disruptive: true}}, nil
		}
	}
	if old != nil {
		if err := c.Health(ctx, next); err != nil {
			return []apply.Action{{Kind: "update", Target: "Multi-WAN", Detail: err.Error(), Disruptive: true}}, nil
		}
	}
	return nil, nil
}

// Apply возвращает маршруты, которые монитор мог снять до перезапуска или
// изменения конфигурации. После успешного применения Run начнёт новый цикл.
func (c *Controller) Apply(ctx context.Context, cfg *config.Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.load(); err != nil {
		return err
	}
	for id, line := range c.suppressed {
		if err := c.restore(ctx, line); err != nil {
			return fmt.Errorf("восстановление аплинка %s: %w", id, err)
		}
	}
	c.suppressed = map[string]string{}
	c.states = map[string]*linkState{}
	c.pausedUntil = time.Now().Add(15 * time.Second)
	if err := c.save(); err != nil {
		return err
	}
	if err := c.reconcileBalance(ctx, cfg); err != nil {
		c.balanceDirty = cfg.MultiWAN.Enabled && cfg.MultiWAN.Mode == "balance"
		return err
	}
	c.balanceDirty = false
	return nil
}

func (c *Controller) Health(ctx context.Context, cfg *config.Config) error {
	suppressed, err := readSuppressed(c.StatePath)
	if err != nil {
		return err
	}
	wanByID := map[string]config.WAN{}
	for _, wan := range cfg.WANs {
		if wan.Enabled {
			wanByID[wan.ID] = wan
		}
	}
	if len(suppressed) > 0 && (!cfg.MultiWAN.Enabled || cfg.MultiWAN.Mode != "failover") {
		return fmt.Errorf("подавленные маршруты остались вне режима failover")
	}
	for id, line := range suppressed {
		wan, ok := wanByID[id]
		if !ok || strings.TrimSpace(line) == "" {
			return fmt.Errorf("состояние подавленного аплинка %s не соответствует конфигурации", id)
		}
		live, err := c.defaultRoute(ctx, interfaceName(cfg, wan))
		if err != nil {
			return err
		}
		if live != "" {
			return fmt.Errorf("маршрут аплинка %s одновременно сохранён как подавленный и присутствует", wan.Name)
		}
	}

	ownedPath := c.balanceOwnedPath()
	var owned []int
	data, err := os.ReadFile(ownedPath)
	if err == nil {
		if err := json.Unmarshal(data, &owned); err != nil {
			return fmt.Errorf("разбор ownership Multi-WAN balance: %w", err)
		}
		info, statErr := os.Stat(ownedPath)
		if statErr != nil {
			return statErr
		}
		if goruntime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			return fmt.Errorf("права ownership Multi-WAN balance: %04o", info.Mode().Perm())
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	var expected []int
	if cfg.MultiWAN.Enabled && cfg.MultiWAN.Mode == "balance" {
		for _, wan := range cfg.WANs {
			if wan.Enabled {
				expected = append(expected, wan.Index)
			}
		}
		sort.Ints(expected)
	}
	if !reflect.DeepEqual(owned, expected) {
		return fmt.Errorf("ownership Multi-WAN balance расходится с конфигурацией")
	}
	if len(expected) == 0 {
		return nil
	}
	rules, err := c.Runner.Run(ctx, "ip", "-4", "rule", "show")
	if err != nil {
		return err
	}
	for _, wan := range cfg.WANs {
		if !wan.Enabled {
			continue
		}
		table := fmt.Sprint(Table(wan))
		routes, err := c.Runner.Run(ctx, "ip", "-4", "route", "show", "table", table)
		if err != nil {
			if !missingFIBTable(err) {
				return err
			}
			routes = ""
		}
		if !hasBlackholeDefault(routes) {
			return fmt.Errorf("в таблице balance %s нет защитного blackhole default", wan.Name)
		}
		if !hasBalanceRule(rules, fmt.Sprint(Priority(wan)), fmt.Sprintf("0x%x", Mark(wan)), table) {
			return fmt.Errorf("правило balance %s отсутствует или указывает не в ту таблицу", wan.Name)
		}
	}
	return nil
}

func readSuppressed(path string) (map[string]string, error) {
	out := map[string]string{}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("разбор состояния подавленных маршрутов: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if goruntime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("права состояния подавленных маршрутов: %04o", info.Mode().Perm())
	}
	return out, nil
}

func hasBlackholeDefault(routes string) bool {
	for _, line := range strings.Split(routes, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "blackhole" && fields[1] == "default" {
			return true
		}
	}
	return false
}

func (c *Controller) Run(ctx context.Context, current func() *config.Config) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	defer c.restoreAll()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.tick(ctx, current())
		}
	}
}

func (c *Controller) restoreAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for id, line := range c.suppressed {
		if err := c.restore(ctx, line); err != nil {
			c.Logger.Warnf("Multi-WAN: маршрут %s не восстановлен при остановке: %v", id, err)
			continue
		}
		delete(c.suppressed, id)
	}
	_ = c.save()
}

func (c *Controller) tick(ctx context.Context, cfg *config.Config) {
	if cfg == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Now().Before(c.pausedUntil) {
		return
	}
	if c.states == nil {
		c.states = map[string]*linkState{}
	}
	if c.suppressed == nil {
		if err := c.load(); err != nil {
			c.Logger.Warnf("Multi-WAN: состояние подавленных маршрутов не загружено: %v", err)
			return
		}
	}
	wanted := map[string]bool{}
	balanceChanged := false
	if cfg.MultiWAN.Enabled {
		for _, wan := range cfg.WANs {
			if !wan.Enabled || !wan.Probe.Enabled {
				continue
			}
			wanted[wan.ID] = true
			state := c.states[wan.ID]
			if state == nil {
				state = &linkState{}
				c.states[wan.ID] = state
			}
			if time.Now().Before(state.Next) {
				continue
			}
			interval := time.Duration(wan.Probe.Interval) * time.Second
			if interval <= 0 {
				interval = 10 * time.Second
			}
			state.Next = time.Now().Add(interval)
			iface := interfaceName(cfg, wan)
			ok := iface != "" && c.Probe(ctx, wan, iface)
			if c.record(ctx, wan, iface, state, ok, cfg.MultiWAN.Mode == "failover") {
				balanceChanged = true
			}
		}
	}
	if cfg.MultiWAN.Enabled && cfg.MultiWAN.Mode == "balance" {
		c.balanceDirty = c.balanceDirty || balanceChanged
		if c.balanceDirty {
			if err := c.reconcileBalance(ctx, cfg); err != nil {
				c.Logger.Warnf("Multi-WAN: balance state не пересобран: %v", err)
			} else {
				c.balanceDirty = false
			}
		}
	} else {
		c.balanceDirty = false
	}
	for id, line := range c.suppressed {
		if wanted[id] {
			continue
		}
		if err := c.restore(ctx, line); err != nil {
			c.Logger.Warnf("Multi-WAN: восстановление %s: %v", id, err)
			continue
		}
		delete(c.suppressed, id)
		delete(c.states, id)
		_ = c.save()
	}
}

func (c *Controller) record(ctx context.Context, wan config.WAN, iface string, state *linkState, ok, suppress bool) bool {
	fail := wan.Probe.FailThreshold
	if fail <= 0 {
		fail = 3
	}
	rise := wan.Probe.RiseThreshold
	if rise <= 0 {
		rise = 2
	}
	if ok {
		state.Failures = 0
		state.Successes++
		if state.Down && state.Successes >= rise {
			if suppress {
				if err := c.restore(ctx, c.suppressed[wan.ID]); err != nil {
					c.Logger.Warnf("Multi-WAN: %s снова доступен, маршрут не восстановлен: %v", wan.Name, err)
					return false
				}
			}
			delete(c.suppressed, wan.ID)
			state.Down = false
			_ = c.save()
			c.Logger.Infof("Multi-WAN: аплинк %s восстановлен", wan.Name)
			return true
		}
		return false
	}
	state.Successes = 0
	state.Failures++
	if state.Down || state.Failures < fail {
		return false
	}
	if !suppress {
		state.Down = true
		c.Logger.Warnf("Multi-WAN: аплинк %s недоступен", wan.Name)
		return true
	}
	line, err := c.defaultRoute(ctx, iface)
	if err != nil {
		c.Logger.Warnf("Multi-WAN: маршрут %s: %v", wan.Name, err)
		return false
	}
	if line == "" {
		return false
	}
	if _, err := c.Runner.Run(ctx, "ip", append([]string{"-4", "route", "del"}, strings.Fields(line)...)...); err != nil {
		c.Logger.Warnf("Multi-WAN: отключение %s: %v", wan.Name, err)
		return false
	}
	c.suppressed[wan.ID] = line
	state.Down = true
	if err := c.save(); err != nil {
		c.Logger.Warnf("Multi-WAN: состояние отключённого аплинка %s не сохранено: %v", wan.Name, err)
		// Without durable state a daemon crash would permanently lose the
		// removed default route. Put it back immediately; if that fails, keep
		// the in-memory entry so restoreAll still gets another chance.
		if restoreErr := c.restore(ctx, line); restoreErr != nil {
			c.Logger.Warnf("Multi-WAN: маршрут %s не восстановлен после ошибки сохранения: %v", wan.Name, restoreErr)
			return false
		}
		delete(c.suppressed, wan.ID)
		state.Down = false
		return false
	}
	c.Logger.Warnf("Multi-WAN: аплинк %s недоступен, выбран резервный", wan.Name)
	return true
}

func (c *Controller) defaultRoute(ctx context.Context, iface string) (string, error) {
	out, err := c.Runner.Run(ctx, "ip", "-4", "route", "show", "default", "dev", iface)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			line = strings.TrimSpace(line)
			// При фильтре `route show ... dev X` iproute2 опускает `dev X`
			// из вывода. Для последующего восстановления возвращаем его явно.
			if !strings.Contains(" "+line+" ", " dev ") {
				line += " dev " + iface
			}
			return line, nil
		}
	}
	return "", nil
}

func (c *Controller) restore(ctx context.Context, line string) error {
	if line == "" {
		return nil
	}
	_, err := c.Runner.Run(ctx, "ip", append([]string{"-4", "route", "replace"}, strings.Fields(line)...)...)
	return err
}

func (c *Controller) probe(ctx context.Context, wan config.WAN, iface string) bool {
	timeout := wan.Probe.Timeout
	if timeout <= 0 {
		timeout = 3
	}
	for _, target := range wan.Probe.Targets {
		var err error
		switch wan.Probe.Type {
		case "http":
			_, err = c.Runner.Run(ctx, "curl", "--interface", iface, "--fail", "--silent", "--max-time", fmt.Sprint(timeout), target)
		case "tcp":
			host, port, splitErr := net.SplitHostPort(target)
			if splitErr != nil {
				continue
			}
			err = probeTCP(ctx, iface, net.JoinHostPort(host, port), time.Duration(timeout)*time.Second)
		default:
			family := "-4"
			if ip := net.ParseIP(target); ip != nil && ip.To4() == nil {
				family = "-6"
			}
			_, err = c.Runner.Run(ctx, "ping", family, "-I", iface, "-c", "1", "-W", fmt.Sprint(timeout), target)
		}
		if err == nil {
			return true
		}
	}
	return false
}

func interfaceName(cfg *config.Config, wan config.WAN) string {
	if wan.Proto == "pppoe" || wan.Proto == "l2tp" {
		return "ppp-" + wan.ID
	}
	return cfg.InterfaceName(wan.Interface)
}

type balanceKernelSnapshot struct {
	index  int
	routes string
	rule   string
}

type balanceOwnedSnapshot struct {
	existed bool
	data    []byte
	mode    os.FileMode
}

func captureOwnedFile(path string) (balanceOwnedSnapshot, error) {
	var snapshot balanceOwnedSnapshot
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return snapshot, nil
	}
	if err != nil {
		return snapshot, err
	}
	if !info.Mode().IsRegular() {
		return snapshot, fmt.Errorf("ownership Multi-WAN %s не является обычным файлом", path)
	}
	snapshot.existed = true
	snapshot.mode = info.Mode().Perm()
	snapshot.data, err = os.ReadFile(path)
	return snapshot, err
}

func (c *Controller) captureBalanceKernel(ctx context.Context, indices map[int]bool) ([]balanceKernelSnapshot, error) {
	if len(indices) == 0 {
		return nil, nil
	}
	rules, err := c.Runner.Run(ctx, "ip", "-4", "rule", "show")
	if err != nil {
		return nil, err
	}
	ordered := make([]int, 0, len(indices))
	for index := range indices {
		ordered = append(ordered, index)
	}
	sort.Ints(ordered)
	snapshots := make([]balanceKernelSnapshot, 0, len(ordered))
	for _, index := range ordered {
		routes, err := c.Runner.Run(ctx, "ip", "-4", "route", "show", "table", fmt.Sprint(tableBase+index))
		if err != nil {
			if !missingFIBTable(err) {
				return nil, err
			}
			// Таблицы ещё нет — это чистое состояние перед первым включением
			// балансировки, а не сбой. Ядро на такой запрос отвечает ошибкой
			// «FIB table does not exist», и пока она считалась настоящей,
			// первое же включение балансировки откатывалось целиком.
			routes = ""
		}
		snapshot := balanceKernelSnapshot{index: index, routes: routes}
		prefix := fmt.Sprint(priorityBase+index) + ":"
		for _, line := range strings.Split(rules, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), prefix) {
				snapshot.rule = strings.TrimSpace(line)
				break
			}
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

// missingFIBTable распознаёт отсутствие таблицы маршрутизации.
//
// Пустая таблица и несуществующая для ядра одно и то же, но iproute2 на вторую
// отвечает ненулевым кодом возврата. Судить о результате по одному коду нельзя:
// до первого создания таблицы это штатное состояние.
func missingFIBTable(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "fib table does not exist")
}

func (c *Controller) restoreBalance(ctx context.Context, kernel []balanceKernelSnapshot, ownedPath string, owned balanceOwnedSnapshot) error {
	var failures []string
	for _, snapshot := range kernel {
		table := fmt.Sprint(tableBase + snapshot.index)
		priority := fmt.Sprint(priorityBase + snapshot.index)
		if _, err := c.Runner.Run(ctx, "ip", "-4", "route", "flush", "table", table); err != nil && !missingFIBTable(err) {
			failures = append(failures, err.Error())
			continue
		}
		for _, line := range strings.Split(snapshot.routes, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			args := append([]string{"-4", "route", "replace"}, fields...)
			if !containsField(fields, "table") {
				args = append(args, "table", table)
			}
			if _, err := c.Runner.Run(ctx, "ip", args...); err != nil {
				failures = append(failures, err.Error())
			}
		}
		_, _ = c.Runner.Run(ctx, "ip", "-4", "rule", "del", "priority", priority)
		if snapshot.rule != "" {
			parts := strings.SplitN(snapshot.rule, ":", 2)
			if len(parts) != 2 {
				failures = append(failures, "не удалось разобрать прежнее правило "+snapshot.rule)
			} else {
				args := []string{"-4", "rule", "add", "priority", strings.TrimSpace(parts[0])}
				args = append(args, strings.Fields(parts[1])...)
				if _, err := c.Runner.Run(ctx, "ip", args...); err != nil {
					failures = append(failures, err.Error())
				}
			}
		}
	}
	if owned.existed {
		if err := system.WriteFileAtomic(ownedPath, owned.data, owned.mode); err != nil {
			failures = append(failures, err.Error())
		}
	} else if err := os.Remove(ownedPath); err != nil && !os.IsNotExist(err) {
		failures = append(failures, err.Error())
	}
	if len(failures) > 0 {
		return fmt.Errorf("rollback Multi-WAN balance: %s", strings.Join(failures, "; "))
	}
	return nil
}

func containsField(fields []string, want string) bool {
	for _, field := range fields {
		if field == want {
			return true
		}
	}
	return false
}

func (c *Controller) reconcileBalance(ctx context.Context, cfg *config.Config) error {
	ownedPath := c.balanceOwnedPath()
	var previous []int
	if data, err := os.ReadFile(ownedPath); err == nil {
		if err := json.Unmarshal(data, &previous); err != nil {
			return fmt.Errorf("разбор ownership Multi-WAN balance: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	wanted := map[int]bool{}
	type desiredTable struct {
		wan   config.WAN
		route string
	}
	var desired []desiredTable
	if cfg.MultiWAN.Enabled && cfg.MultiWAN.Mode == "balance" {
		var live []string
		for _, wan := range cfg.WANs {
			if !wan.Enabled {
				continue
			}
			wanted[wan.Index] = true
			line, err := c.defaultRoute(ctx, interfaceName(cfg, wan))
			if err != nil {
				return fmt.Errorf("маршрут аплинка %s: %w", wan.Name, err)
			}
			live = append(live, line)
		}
		fallback := ""
		for i, wan := range enabledWANs(cfg) {
			if st := c.states[wan.ID]; st == nil || !st.Down {
				if i < len(live) && live[i] != "" {
					fallback = live[i]
					break
				}
			}
		}
		i := 0
		for _, wan := range cfg.WANs {
			if !wan.Enabled {
				continue
			}
			route := live[i]
			i++
			if st := c.states[wan.ID]; st != nil && st.Down {
				route = fallback
			}
			desired = append(desired, desiredTable{wan: wan, route: route})
		}
	}
	indices := map[int]bool{}
	for _, index := range previous {
		indices[index] = true
	}
	for index := range wanted {
		indices[index] = true
	}
	ownedSnapshot, err := captureOwnedFile(ownedPath)
	if err != nil {
		return err
	}
	kernelSnapshot, err := c.captureBalanceKernel(ctx, indices)
	if err != nil {
		return err
	}
	rollback := func(cause error) error {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := c.restoreBalance(rollbackCtx, kernelSnapshot, ownedPath, ownedSnapshot); err != nil {
			return fmt.Errorf("%v; %w", cause, err)
		}
		return cause
	}
	kernelByIndex := make(map[int]balanceKernelSnapshot, len(kernelSnapshot))
	for _, snapshot := range kernelSnapshot {
		kernelByIndex[snapshot.index] = snapshot
	}
	for _, item := range desired {
		if err := c.ensureBalanceTable(ctx, item.wan, item.route); err != nil {
			return rollback(err)
		}
	}
	for _, index := range previous {
		if !wanted[index] {
			if kernelByIndex[index].rule != "" {
				if _, err := c.Runner.Run(ctx, "ip", "-4", "rule", "del", "priority", fmt.Sprint(priorityBase+index)); err != nil {
					return rollback(err)
				}
			}
			if _, err := c.Runner.Run(ctx, "ip", "-4", "route", "flush", "table", fmt.Sprint(tableBase+index)); err != nil {
				return rollback(err)
			}
		}
	}
	var next []int
	for index := range wanted {
		next = append(next, index)
	}
	sort.Ints(next)
	if len(next) == 0 {
		if err := os.Remove(ownedPath); err != nil && !os.IsNotExist(err) {
			return rollback(err)
		}
		return nil
	}
	data, _ := json.Marshal(next)
	data = append(data, '\n')
	if system.FileChanged(ownedPath, data) {
		if err := system.WriteFileAtomic(ownedPath, data, 0o600); err != nil {
			return rollback(err)
		}
	}
	return nil
}

func enabledWANs(cfg *config.Config) []config.WAN {
	var out []config.WAN
	for _, wan := range cfg.WANs {
		if wan.Enabled {
			out = append(out, wan)
		}
	}
	return out
}

func (c *Controller) ensureBalanceTable(ctx context.Context, wan config.WAN, route string) error {
	table := fmt.Sprint(Table(wan))
	priority := fmt.Sprint(Priority(wan))
	mark := fmt.Sprintf("0x%x", Mark(wan))
	_, _ = c.Runner.Run(ctx, "ip", "-4", "route", "flush", "table", table)
	if route != "" {
		args := append([]string{"-4", "route", "replace"}, strings.Fields(route)...)
		args = append(args, "table", table)
		if _, err := c.Runner.Run(ctx, "ip", args...); err != nil {
			return fmt.Errorf("таблица аплинка %s: %w", wan.Name, err)
		}
	}
	if _, err := c.Runner.Run(ctx, "ip", "-4", "route", "replace", "blackhole", "default", "metric", "32767", "table", table); err != nil {
		return err
	}
	rules, err := c.Runner.Run(ctx, "ip", "-4", "rule", "show")
	if err != nil {
		return err
	}
	if !hasBalanceRule(rules, priority, mark, table) {
		_, _ = c.Runner.Run(ctx, "ip", "-4", "rule", "del", "priority", priority)
		if _, err := c.Runner.Run(ctx, "ip", "-4", "rule", "add", "fwmark", mark, "priority", priority, "lookup", table); err != nil {
			return err
		}
	}
	return nil
}

func hasBalanceRule(rules, priority, mark, table string) bool {
	for _, line := range strings.Split(rules, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), priority+":") {
			continue
		}
		fields := strings.Fields(line)
		markOK, tableOK := false, false
		for i := 0; i+1 < len(fields); i++ {
			switch fields[i] {
			case "fwmark":
				markOK = strings.SplitN(fields[i+1], "/", 2)[0] == mark
			case "lookup", "table":
				tableOK = fields[i+1] == table
			}
		}
		if markOK && tableOK {
			return true
		}
	}
	return false
}

func (c *Controller) balanceOwnedPath() string {
	return filepath.Join(filepath.Dir(c.StatePath), "multiwan-balance.json")
}

func (c *Controller) load() error {
	suppressed, err := readSuppressed(c.StatePath)
	if err != nil {
		return err
	}
	c.suppressed = suppressed
	return nil
}

func (c *Controller) save() error {
	if len(c.suppressed) == 0 {
		if err := os.Remove(c.StatePath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	data, err := json.MarshalIndent(c.suppressed, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if !system.FileChanged(c.StatePath, data) {
		return nil
	}
	return system.WriteFileAtomic(c.StatePath, data, 0o600)
}
