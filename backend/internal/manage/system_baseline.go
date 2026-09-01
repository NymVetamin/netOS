package manage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/netos-router/netos/internal/subsys/sysctl"
	"github.com/netos-router/netos/internal/system"
)

const systemBaselineDir = "/var/lib/netos-system-baseline"

type serviceBaseline struct {
	Enabled string `json:"enabled,omitempty"`
	Active  string `json:"active,omitempty"`
}

type fileBaseline struct {
	Exists bool   `json:"exists"`
	Mode   uint32 `json:"mode,omitempty"`
	Data   []byte `json:"data,omitempty"`
}

type systemBaseline struct {
	Version         int               `json:"version"`
	IPTables4       string            `json:"iptables4"`
	IPTables6       string            `json:"iptables6,omitempty"`
	IPTables6Exists bool              `json:"iptables6_exists"`
	StaticRoutes4   []string          `json:"static_routes4,omitempty"`
	StaticRoutes6   []string          `json:"static_routes6,omitempty"`
	DefaultRoutes4  []string          `json:"default_routes4,omitempty"`
	DefaultRoutes6  []string          `json:"default_routes6,omitempty"`
	PolicyRules4    []string          `json:"policy_rules4,omitempty"`
	Sysctl          map[string]string `json:"sysctl"`
	Tuned           serviceBaseline   `json:"tuned"`
	Timesyncd       serviceBaseline   `json:"timesyncd"`
	Resolved        serviceBaseline   `json:"resolved"`
	TimesyncdConfig fileBaseline      `json:"timesyncd_config"`
	Hostname        string            `json:"hostname"`
	Timezone        string            `json:"timezone"`
}

// CaptureSystemBaseline records host state before the first netOS Apply. It is
// deliberately a separate explicit installer step: automatically taking a
// snapshot on an upgrade from an old release would preserve netOS-mutated
// state and later misrepresent it as the pre-install state.
func CaptureSystemBaseline(ctx context.Context, runner system.Runner) error {
	return captureSystemBaseline(ctx, runner, "")
}

func captureSystemBaseline(ctx context.Context, runner system.Runner, root string) error {
	dir := rooted(root, systemBaselineDir)
	path := filepath.Join(dir, "state.json")
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("проверка системного baseline: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("создание системного baseline: %w", err)
	}

	b := systemBaseline{Version: 1, Sysctl: map[string]string{}}
	var err error
	if b.IPTables4, err = runner.Run(ctx, "iptables-save"); err != nil {
		return fmt.Errorf("снимок IPv4 firewall: %w", err)
	}
	if b.IPTables6, err = runner.Run(ctx, "ip6tables-save"); err == nil {
		b.IPTables6Exists = true
	}
	if out, routeErr := runner.Run(ctx, "ip", "-4", "route", "show", "table", "all", "proto", "static"); routeErr == nil {
		b.StaticRoutes4 = nonemptyLines(out)
	} else {
		return fmt.Errorf("снимок статических маршрутов IPv4: %w", routeErr)
	}
	if out, routeErr := runner.Run(ctx, "ip", "-6", "route", "show", "table", "all", "proto", "static"); routeErr == nil {
		b.StaticRoutes6 = nonemptyLines(out)
	}
	if out, routeErr := runner.Run(ctx, "ip", "-4", "route", "show", "default"); routeErr == nil {
		b.DefaultRoutes4 = nonemptyLines(out)
	} else {
		return fmt.Errorf("снимок default routes IPv4: %w", routeErr)
	}
	if out, routeErr := runner.Run(ctx, "ip", "-6", "route", "show", "default"); routeErr == nil {
		b.DefaultRoutes6 = nonemptyLines(out)
	}
	if out, ruleErr := runner.Run(ctx, "ip", "-4", "rule", "show"); ruleErr == nil {
		for _, line := range nonemptyLines(out) {
			if priority := baselineRulePriority(line); priority >= 10000 && priority <= 29999 {
				b.PolicyRules4 = append(b.PolicyRules4, line)
			}
		}
	} else {
		return fmt.Errorf("снимок policy rules IPv4: %w", ruleErr)
	}

	for _, key := range sysctl.ManagedKeys() {
		captureSysctlValue(root, key, b.Sysctl)
	}
	confRoot := rooted(root, "/proc/sys/net/ipv6/conf")
	entries, readErr := os.ReadDir(confRoot)
	if readErr == nil {
		for _, entry := range entries {
			if !entry.IsDir() || entry.Name() == "all" || entry.Name() == "default" {
				continue
			}
			for _, key := range sysctl.ManagedPerInterfaceIPv6Keys() {
				captureSysctlPath(root, filepath.Join("net", "ipv6", "conf", entry.Name(), key), b.Sysctl)
			}
		}
	} else if !os.IsNotExist(readErr) {
		return fmt.Errorf("снимок IPv6 sysctl интерфейсов: %w", readErr)
	}
	b.Tuned.Enabled = commandState(ctx, runner, "is-enabled", "tuned.service")
	b.Tuned.Active = commandState(ctx, runner, "is-active", "tuned.service")
	b.Timesyncd.Enabled = commandState(ctx, runner, "is-enabled", "systemd-timesyncd.service")
	b.Timesyncd.Active = commandState(ctx, runner, "is-active", "systemd-timesyncd.service")
	b.Resolved.Enabled = commandState(ctx, runner, "is-enabled", "systemd-resolved.service")
	b.Resolved.Active = commandState(ctx, runner, "is-active", "systemd-resolved.service")
	if b.Hostname, err = runner.Run(ctx, "hostnamectl", "--static"); err != nil {
		return fmt.Errorf("снимок имени машины: %w", err)
	}
	b.Hostname = strings.TrimSpace(b.Hostname)
	if b.Timezone, err = runner.Run(ctx, "timedatectl", "show", "--property=Timezone", "--value"); err != nil {
		return fmt.Errorf("снимок часового пояса: %w", err)
	}
	b.Timezone = strings.TrimSpace(b.Timezone)
	if b.TimesyncdConfig, err = captureFileBaseline(rooted(root, "/etc/systemd/timesyncd.conf.d/90-netos.conf")); err != nil {
		return fmt.Errorf("снимок конфигурации timesyncd: %w", err)
	}

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if err := system.WriteFileAtomic(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("запись системного baseline: %w", err)
	}
	return nil
}

func rooted(root, path string) string {
	if root == "" {
		return path
	}
	return filepath.Join(root, path)
}

func captureSysctlValue(root, key string, dst map[string]string) {
	captureSysctlPath(root, filepath.Join(strings.Split(key, ".")...), dst)
}

func captureSysctlPath(root, relative string, dst map[string]string) {
	path := rooted(root, filepath.Join("/proc/sys", relative))
	if data, err := os.ReadFile(path); err == nil {
		dst[filepath.ToSlash(relative)] = strings.TrimSpace(string(data))
	}
}

func commandState(ctx context.Context, runner system.Runner, verb, unit string) string {
	out, _ := runner.Run(ctx, "systemctl", verb, unit)
	return strings.TrimSpace(out)
}

func captureFileBaseline(path string) (fileBaseline, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return fileBaseline{}, nil
	}
	if err != nil {
		return fileBaseline{}, err
	}
	if !info.Mode().IsRegular() {
		return fileBaseline{}, fmt.Errorf("%s не является обычным файлом", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fileBaseline{}, err
	}
	return fileBaseline{Exists: true, Mode: uint32(info.Mode().Perm()), Data: data}, nil
}

func nonemptyLines(value string) []string {
	var out []string
	for _, line := range strings.Split(value, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

func baselineRulePriority(line string) int {
	first, _, _ := strings.Cut(strings.TrimSpace(line), ":")
	value, err := strconv.Atoi(first)
	if err != nil {
		return -1
	}
	return value
}

func (m *Manager) readSystemBaseline() (*systemBaseline, error) {
	data, err := os.ReadFile(filepath.Join(m.sys(systemBaselineDir), "state.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var b systemBaseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("разбор системного baseline: %w", err)
	}
	if b.Version != 1 || b.IPTables4 == "" || b.Sysctl == nil {
		return nil, errors.New("системный baseline неполон или имеет неизвестную версию")
	}
	return &b, nil
}

func (m *Manager) restoreBaselineFirewall(ctx context.Context, b *systemBaseline) error {
	if err := m.Run(ctx, command{name: "iptables-restore", stdin: b.IPTables4}); err != nil {
		return fmt.Errorf("восстановление IPv4 firewall: %w", err)
	}
	if b.IPTables6Exists {
		if err := m.Run(ctx, command{name: "ip6tables-restore", stdin: b.IPTables6}); err != nil {
			return fmt.Errorf("восстановление IPv6 firewall: %w", err)
		}
	}
	return nil
}

func (m *Manager) restoreBaselineRouting(ctx context.Context, b *systemBaseline) error {
	for _, item := range []struct {
		family string
		lines  []string
	}{
		{"-4", append(append([]string(nil), b.StaticRoutes4...), b.DefaultRoutes4...)},
		{"-6", append(append([]string(nil), b.StaticRoutes6...), b.DefaultRoutes6...)},
	} {
		seen := map[string]bool{}
		for _, line := range item.lines {
			if seen[line] {
				continue
			}
			seen[line] = true
			args := append([]string{item.family, "route", "replace"}, strings.Fields(line)...)
			if err := m.run(ctx, "ip", args...); err != nil {
				return fmt.Errorf("восстановление маршрута %q: %w", line, err)
			}
		}
	}
	for _, line := range b.PolicyRules4 {
		priority := baselineRulePriority(line)
		if priority < 10000 || priority > 29999 {
			continue
		}
		_, tail, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		args := []string{"-4", "rule", "add", "priority", strconv.Itoa(priority)}
		args = append(args, strings.Fields(tail)...)
		if err := m.run(ctx, "ip", args...); err != nil {
			return fmt.Errorf("восстановление policy rule %q: %w", line, err)
		}
	}
	return nil
}

func (m *Manager) restoreBaselineSysctl(b *systemBaseline) error {
	keys := make([]string, 0, len(b.Sysctl))
	for key := range b.Sysctl {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		path := filepath.Join(m.sys("/proc/sys"), filepath.FromSlash(key))
		if err := os.WriteFile(path, []byte(b.Sysctl[key]), 0o644); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("восстановление sysctl %s: %w", key, err)
		}
	}
	return nil
}

func (m *Manager) restoreBaselineTuned(ctx context.Context, b *systemBaseline) error {
	return m.restoreServiceBaseline(ctx, "tuned.service", b.Tuned)
}

func (m *Manager) restoreBaselineHostSettings(ctx context.Context, b *systemBaseline) error {
	if b.Hostname != "" {
		if err := m.run(ctx, "hostnamectl", "set-hostname", b.Hostname); err != nil {
			return fmt.Errorf("восстановление имени машины: %w", err)
		}
	}
	if b.Timezone != "" {
		if err := m.run(ctx, "timedatectl", "set-timezone", b.Timezone); err != nil {
			return fmt.Errorf("восстановление часового пояса: %w", err)
		}
	}
	path := m.sys("/etc/systemd/timesyncd.conf.d/90-netos.conf")
	if b.TimesyncdConfig.Exists {
		mode := os.FileMode(b.TimesyncdConfig.Mode)
		if mode == 0 {
			mode = 0o644
		}
		if err := system.WriteFileAtomic(path, b.TimesyncdConfig.Data, mode); err != nil {
			return fmt.Errorf("восстановление конфигурации timesyncd: %w", err)
		}
	} else if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("удаление конфигурации timesyncd netOS: %w", err)
	}
	if err := m.restoreServiceBaseline(ctx, "systemd-timesyncd.service", b.Timesyncd); err != nil {
		return fmt.Errorf("восстановление timesyncd: %w", err)
	}
	if b.Timesyncd.Active == "active" {
		if err := m.run(ctx, "systemctl", "restart", "systemd-timesyncd.service"); err != nil {
			return fmt.Errorf("перечитывание восстановленной конфигурации timesyncd: %w", err)
		}
	}
	return nil
}

func (m *Manager) restoreBaselineResolved(ctx context.Context, b *systemBaseline) error {
	return m.restoreServiceBaseline(ctx, "systemd-resolved.service", b.Resolved)
}

func (m *Manager) restoreServiceBaseline(ctx context.Context, unit string, state serviceBaseline) error {
	switch state.Enabled {
	case "enabled":
		if err := m.run(ctx, "systemctl", "enable", unit); err != nil {
			return err
		}
	case "enabled-runtime":
		if err := m.run(ctx, "systemctl", "enable", "--runtime", unit); err != nil {
			return err
		}
	case "disabled":
		if err := m.run(ctx, "systemctl", "disable", unit); err != nil {
			return err
		}
	case "masked":
		if err := m.run(ctx, "systemctl", "mask", unit); err != nil {
			return err
		}
	case "masked-runtime":
		if err := m.run(ctx, "systemctl", "mask", "--runtime", unit); err != nil {
			return err
		}
	}
	switch state.Active {
	case "active", "activating", "reloading":
		return m.run(ctx, "systemctl", "start", unit)
	case "inactive", "failed", "deactivating":
		return m.run(ctx, "systemctl", "stop", unit)
	}
	return nil
}

type ownedLinkRecord struct {
	Name      string `json:"name"`
	Interface string `json:"interface"`
	IFB       string `json:"ifb"`
}

// ownedVirtualInterfaceNames reads the exact ownership journals maintained by
// the interface, channel, VPN-server and QoS subsystems. A name prefix is not
// ownership: administrators and container runtimes commonly create br-* and
// bond-* links of their own.
func (m *Manager) ownedVirtualInterfaceNames() (map[string]bool, error) {
	names := map[string]bool{}
	var problems []string
	ownedLinks := filepath.Join(m.StateDir, "owned-links")
	if data, err := os.ReadFile(ownedLinks); err == nil {
		for _, name := range nonemptyLines(string(data)) {
			if validLinkName(name) {
				names[name] = true
			} else {
				problems = append(problems, fmt.Sprintf("некорректное имя в %s: %q", ownedLinks, name))
			}
		}
	} else if !os.IsNotExist(err) {
		problems = append(problems, fmt.Sprintf("%s: %v", ownedLinks, err))
	}

	for _, path := range []string{
		filepath.Join(m.StateDir, "generated", "owned-channels.json"),
		filepath.Join(m.StateDir, "generated", "owned-vpn-servers.json"),
		filepath.Join(m.StateDir, "generated", "owned-qos.json"),
	} {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		var records []ownedLinkRecord
		if err := json.Unmarshal(data, &records); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		for _, record := range records {
			for _, name := range []string{record.Name, record.IFB} {
				if name == "" {
					continue
				}
				if validLinkName(name) {
					names[name] = true
				} else {
					problems = append(problems, fmt.Sprintf("некорректное имя в %s: %q", path, name))
				}
			}
		}
	}
	if len(problems) > 0 {
		return names, errors.New(strings.Join(problems, "; "))
	}
	return names, nil
}

func validLinkName(name string) bool {
	return name != "" && name != "." && name != ".." && len(name) <= 15 &&
		!strings.ContainsAny(name, "/\\\x00\r\n\t ")
}

func legacyUnambiguousNetOSLink(name string) bool {
	for _, prefix := range []string{"wg-ch", "tun-ch", "wg-srv", "xfrm-ch", "xfrm-srv", "ifb-netos-"} {
		if suffix := strings.TrimPrefix(name, prefix); suffix != name && suffix != "" {
			if _, err := strconv.Atoi(suffix); err == nil {
				return true
			}
		}
	}
	return false
}

func (m *Manager) removeOwnedQoS(ctx context.Context) {
	interfaces := map[string]bool{}
	wanPath := filepath.Join(m.StateDir, "generated", "owned-qos.json")
	if data, err := os.ReadFile(wanPath); err == nil {
		var records []ownedLinkRecord
		if err := json.Unmarshal(data, &records); err != nil {
			fmt.Fprintf(m.Err, "Предупреждение: чтение QoS ownership %s: %v\n", wanPath, err)
		} else {
			for _, record := range records {
				if validLinkName(record.Interface) {
					interfaces[record.Interface] = true
				}
			}
		}
	} else if !os.IsNotExist(err) {
		fmt.Fprintf(m.Err, "Предупреждение: чтение QoS ownership %s: %v\n", wanPath, err)
	}
	clientPath := filepath.Join(m.StateDir, "generated", "owned-qos-clients.json")
	if data, err := os.ReadFile(clientPath); err == nil {
		var names []string
		if err := json.Unmarshal(data, &names); err != nil {
			fmt.Fprintf(m.Err, "Предупреждение: чтение QoS ownership %s: %v\n", clientPath, err)
		} else {
			for _, name := range names {
				if validLinkName(name) {
					interfaces[name] = true
				}
			}
		}
	} else if !os.IsNotExist(err) {
		fmt.Fprintf(m.Err, "Предупреждение: чтение QoS ownership %s: %v\n", clientPath, err)
	}
	for name := range interfaces {
		m.bestEffort(ctx, "tc", "qdisc", "del", "dev", name, "root")
		m.bestEffort(ctx, "tc", "qdisc", "del", "dev", name, "ingress")
	}
}
