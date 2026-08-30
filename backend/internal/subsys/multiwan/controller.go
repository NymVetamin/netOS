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

	mu          sync.Mutex
	states      map[string]*linkState
	suppressed  map[string]string
	pausedUntil time.Time
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
	c := &Controller{Runner: r, StatePath: filepath.Join(stateDir, "multiwan-suppressed.json"), Logger: logger}
	c.Probe = c.probe
	return c
}

func (c *Controller) Name() string { return "multiwan" }

func (c *Controller) Plan(old, next *config.Config) ([]apply.Action, error) {
	if old == nil || !reflect.DeepEqual(old.MultiWAN, next.MultiWAN) || !reflect.DeepEqual(old.WANs, next.WANs) {
		if next.MultiWAN.Enabled {
			return []apply.Action{{Kind: "update", Target: "Multi-WAN failover", Detail: "пробы доступности", Disruptive: true}}, nil
		}
		if old != nil && old.MultiWAN.Enabled {
			return []apply.Action{{Kind: "delete", Target: "Multi-WAN failover", Disruptive: true}}, nil
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
	return c.reconcileBalance(ctx, cfg)
}

func (c *Controller) Health(context.Context, *config.Config) error { return nil }

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
		_ = c.load()
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
	if balanceChanged && cfg.MultiWAN.Enabled && cfg.MultiWAN.Mode == "balance" {
		_ = c.reconcileBalance(ctx, cfg)
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
	_ = c.save()
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
			_, err = c.Runner.Run(ctx, "curl", "--interface", iface, "--silent", "--max-time", fmt.Sprint(timeout), "telnet://"+host+":"+port)
		default:
			_, err = c.Runner.Run(ctx, "ping", "-4", "-I", iface, "-c", "1", "-W", fmt.Sprint(timeout), target)
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

func (c *Controller) reconcileBalance(ctx context.Context, cfg *config.Config) error {
	ownedPath := filepath.Join(filepath.Dir(c.StatePath), "multiwan-balance.json")
	var previous []int
	if data, err := os.ReadFile(ownedPath); err == nil {
		_ = json.Unmarshal(data, &previous)
	}
	wanted := map[int]bool{}
	if cfg.MultiWAN.Enabled && cfg.MultiWAN.Mode == "balance" {
		var live []string
		for _, wan := range cfg.WANs {
			if !wan.Enabled {
				continue
			}
			wanted[wan.Index] = true
			line, _ := c.defaultRoute(ctx, interfaceName(cfg, wan))
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
			if err := c.ensureBalanceTable(ctx, wan, route); err != nil {
				return err
			}
		}
	}
	for _, index := range previous {
		if !wanted[index] {
			_, _ = c.Runner.Run(ctx, "ip", "-4", "rule", "del", "priority", fmt.Sprint(priorityBase+index))
			_, _ = c.Runner.Run(ctx, "ip", "-4", "route", "flush", "table", fmt.Sprint(tableBase+index))
		}
	}
	var next []int
	for index := range wanted {
		next = append(next, index)
	}
	sort.Ints(next)
	if len(next) == 0 {
		if err := os.Remove(ownedPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	data, _ := json.Marshal(next)
	data = append(data, '\n')
	if system.FileChanged(ownedPath, data) {
		return system.WriteFileAtomic(ownedPath, data, 0o600)
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
	if !strings.Contains(rules, priority+":") || !strings.Contains(rules, "fwmark "+mark) {
		_, _ = c.Runner.Run(ctx, "ip", "-4", "rule", "del", "priority", priority)
		if _, err := c.Runner.Run(ctx, "ip", "-4", "rule", "add", "fwmark", mark, "priority", priority, "lookup", table); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) load() error {
	c.suppressed = map[string]string{}
	data, err := os.ReadFile(c.StatePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &c.suppressed)
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
