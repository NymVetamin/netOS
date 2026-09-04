package services

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

var (
	iscConfPath  = "/var/lib/netos/generated/dhcpd.conf"
	iscLeasePath = "/var/lib/netos/dhcpd.leases"
	iscUnit      = "netos-isc-dhcp.service"
)

type ISCDHCP struct {
	Runner  system.Runner
	Systemd *system.Systemd
}

func NewISCDHCP(r system.Runner) *ISCDHCP { return &ISCDHCP{Runner: r, Systemd: system.NewSystemd(r)} }
func (d *ISCDHCP) Needed(cfg *config.Config) bool {
	return cfg.DHCP.Enabled && cfg.DHCP.Provider == "isc-dhcp-server"
}

func (d *ISCDHCP) Render(cfg *config.Config) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("# Сгенерировано netOS. Правки будут перезаписаны при следующем применении.")
	w("authoritative;")
	w("ddns-update-style none;")
	w("")

	custom := map[string]string{}
	for _, n := range cfg.Networks {
		if !n.Enabled || !n.DHCPPool.Enabled {
			continue
		}
		codes := make([]string, 0, len(n.DHCPPool.Options))
		for code := range n.DHCPPool.Options {
			codes = append(codes, code)
		}
		sort.Strings(codes)
		for _, code := range codes {
			if _, ok := iscOptionName(code); !ok {
				custom[code] = "netos-option-" + code
			}
		}
	}
	codes := make([]string, 0, len(custom))
	for code := range custom {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	for _, code := range codes {
		if n, err := strconv.Atoi(code); err == nil && n >= 1 && n <= 254 {
			w("option %s code %d = string;", custom[code], n)
		}
	}
	if len(codes) > 0 {
		w("")
	}

	for _, n := range cfg.Networks {
		if !n.Enabled || !n.DHCPPool.Enabled {
			continue
		}
		prefix, err := netip.ParsePrefix(n.RouterAddress)
		if err != nil {
			continue
		}
		mask, err := netmaskOf(n.RouterAddress)
		if err != nil {
			continue
		}
		p := n.DHCPPool
		w("subnet %s netmask %s {", prefix.Masked().Addr(), mask)
		w("  range %s %s;", p.Start, p.End)
		w("  default-lease-time %d;", p.LeaseTime)
		w("  max-lease-time %d;", p.LeaseTime)
		gateway := p.Gateway
		if gateway == "" {
			gateway = addressOf(n.RouterAddress)
		}
		w("  option routers %s;", gateway)
		dns := p.DNSServers
		if len(dns) == 0 {
			dns = []string{addressOf(n.RouterAddress)}
		}
		w("  option domain-name-servers %s;", strings.Join(dns, ", "))
		if p.Domain != "" {
			w("  option domain-name %q;", p.Domain)
		}
		codes := make([]string, 0, len(p.Options))
		for code := range p.Options {
			codes = append(codes, code)
		}
		sort.Strings(codes)
		for _, code := range codes {
			name, known := iscOptionName(code)
			if known {
				w("  option %s %s;", name, iscOptionValue(code, p.Options[code]))
			} else if custom[code] != "" {
				w("  option %s %q;", custom[code], p.Options[code])
			}
		}
		w("}")
		w("")
	}
	blocked := map[string]bool{}
	for _, cl := range cfg.Clients {
		if cl.Blocked {
			blocked[strings.ToLower(cl.MAC)] = true
		}
	}
	for _, res := range cfg.DHCP.Reservations {
		if !res.Enabled {
			continue
		}
		if blocked[strings.ToLower(res.MAC)] {
			continue
		}
		w("host netos-%s {", safeDHCPName(res.ID))
		w("  hardware ethernet %s;", res.MAC)
		w("  fixed-address %s;", res.IP)
		if res.Hostname != "" {
			w("  option host-name %q;", res.Hostname)
		}
		w("}")
	}
	for i, cl := range cfg.Clients {
		if cl.Blocked && cl.MAC != "" {
			w("host netos-blocked-%d { hardware ethernet %s; deny booting; }", i+1, cl.MAC)
		}
	}
	if cfg.DHCP.AdvancedOptions != "" {
		w("")
		w("# Дополнительные директивы пользователя")
		w("%s", strings.TrimSpace(cfg.DHCP.AdvancedOptions))
	}
	return b.String()
}

func iscOptionName(code string) (string, bool) {
	names := map[string]string{"1": "subnet-mask", "3": "routers", "6": "domain-name-servers", "12": "host-name", "15": "domain-name", "28": "broadcast-address", "42": "ntp-servers", "66": "tftp-server-name", "67": "bootfile-name"}
	v, ok := names[code]
	return v, ok
}
func iscOptionValue(code, value string) string {
	switch code {
	case "12", "15", "66", "67":
		return strconv.Quote(value)
	default:
		return value
	}
}
func safeDHCPName(v string) string {
	var b strings.Builder
	for _, r := range v {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "reservation"
	}
	return b.String()
}

func (d *ISCDHCP) interfaces(cfg *config.Config) []string {
	byID := map[string]string{}
	for _, i := range cfg.Interfaces {
		byID[i.ID] = i.Name
	}
	seen := map[string]bool{}
	var out []string
	for _, n := range cfg.Networks {
		if n.Enabled && n.DHCPPool.Enabled {
			if name := byID[n.Interface]; name != "" && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}
func (d *ISCDHCP) Apply(ctx context.Context, cfg *config.Config) error {
	if !d.Needed(cfg) {
		if err := removeManagedUnit(ctx, d.Systemd, iscUnit); err != nil {
			return err
		}
		return removeGenerated(iscConfPath)
	}
	if len(d.interfaces(cfg)) == 0 {
		return fmt.Errorf("ISC DHCP: нет включённых пулов на доступных интерфейсах")
	}
	lease, err := os.OpenFile(iscLeasePath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := lease.Close(); err != nil {
		return err
	}
	if err := os.Chmod(iscLeasePath, 0o600); err != nil {
		return err
	}
	content := []byte(d.Render(cfg))
	if err := validateManagedContent(iscConfPath, content, 0o644, func(path string) error {
		if _, err := d.Runner.Run(ctx, "dhcpd", "-4", "-t", "-cf", path, "-lf", iscLeasePath); err != nil {
			return fmt.Errorf("проверка конфигурации ISC DHCP: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}
	changed, err := writeManagedFile(iscConfPath, content, 0o644)
	if err != nil {
		return err
	}
	if err := d.ensureUnit(ctx, cfg); err != nil {
		return err
	}
	if !changed && d.Systemd.IsActive(ctx, iscUnit) {
		return nil
	}
	return d.Systemd.Restart(ctx, iscUnit)
}
func (d *ISCDHCP) ensureUnit(ctx context.Context, cfg *config.Config) error {
	changed, err := writeManagedFile(filepath.Join(systemdUnitDir, iscUnit), []byte(d.unitContent(cfg)), 0o644)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	return d.Systemd.DaemonReload(ctx)
}

func (d *ISCDHCP) unitContent(cfg *config.Config) string {
	args := strings.Join(d.interfaces(cfg), " ")
	return "[Unit]\nDescription=netOS ISC DHCPv4\nAfter=network.target\nWants=network.target\n\n[Service]\nType=simple\nExecStart=/usr/sbin/dhcpd -4 -f -q -cf " + iscConfPath + " -lf " + iscLeasePath + " --no-pid " + args + "\nRestart=always\nRestartSec=2\nUMask=0077\n\n[Install]\nWantedBy=multi-user.target\n"
}
func (d *ISCDHCP) Health(ctx context.Context, cfg *config.Config) error {
	if !d.Needed(cfg) {
		if d.Systemd.IsActive(ctx, iscUnit) {
			return fmt.Errorf("ISC DHCP запущен, хотя не выбран")
		}
		return generatedAbsent(iscConfPath)
	}
	if !d.Systemd.IsActive(ctx, iscUnit) {
		return fmt.Errorf("ISC DHCP не запущен")
	}
	if err := managedFileHealth(iscConfPath, []byte(d.Render(cfg)), 0o644); err != nil {
		return err
	}
	if err := managedFileModeHealth(iscLeasePath, 0o600, true); err != nil {
		return err
	}
	return managedFileHealth(filepath.Join(systemdUnitDir, iscUnit), []byte(d.unitContent(cfg)), 0o644)
}
