package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

var (
	dnsproxyConfPath  = "/var/lib/netos/generated/dnsproxy.yaml"
	dnsproxyHostsPath = "/var/lib/netos/generated/dnsproxy-hosts"
	dnsproxyBinary    = "/usr/local/bin/dnsproxy"
	dnsproxyUnit      = "netos-dnsproxy.service"
)

// Dnsproxy владеет процессом dnsproxy.
//
// В отличие от unbound он умеет DoH и DoQ; AAAA вырезает своей встроенной опцией.
// Для роутера, который подавляет IPv6, это не мелочь: клиент,
// получивший AAAA, попытается пойти в обход канала.
//
// Локальные имена, как и в связке с unbound, остаются за dnsmasq: адреса
// раздаёт он и только он знает, какое имя за каким клиентом закреплено.
type Dnsproxy struct {
	Runner  system.Runner
	Systemd *system.Systemd
}

func NewDnsproxy(r system.Runner) *Dnsproxy {
	return &Dnsproxy{Runner: r, Systemd: system.NewSystemd(r)}
}

func (d *Dnsproxy) Needed(cfg *config.Config) bool {
	return cfg.DNS.Enabled && cfg.DNS.Provider == "dnsproxy"
}

// Render собирает конфигурацию dnsproxy.
//
// Ключи проверены на выпущенном бинарнике: dnsproxy принимает YAML, в котором
// имена полей повторяют длинные флаги командной строки.
func (d *Dnsproxy) Render(cfg *config.Config) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("# Сгенерировано netOS. Правки будут перезаписаны при следующем применении.")
	w("---")

	// Слушаем на loopback и на адресе роутера в каждом сегменте: на всех
	// адресах подряд нельзя, иначе резолвер окажется открыт со стороны аплинка.
	w("listen-addrs:")
	w("  - \"127.0.0.1\"")
	policyBackend := hasKernelDomainPolicies(cfg) && cfg.DNS.Provider == "dnsproxy"
	for _, n := range cfg.Networks {
		if policyBackend {
			break
		}
		if !n.Enabled || n.RouterAddress == "" {
			continue
		}
		w("  - %q", addressOf(n.RouterAddress))
	}
	w("listen-ports:")
	if policyBackend {
		w("  - %d", policyDNSBackendPort)
	} else {
		w("  - %d", cfg.DNS.Port)
	}

	w("upstream:")
	// Локальная зона уходит в dnsmasq: только он знает имена клиентов.
	if backendLocalDNSNeeded(cfg) {
		for _, zone := range localZones(cfg) {
			w("  - \"[/%s/]127.0.0.1:%d\"", zone, dnsmasqLocalPort)
		}
	}
	upstreamByID := map[string]config.Upstream{}
	for _, up := range cfg.DNS.Upstreams {
		upstreamByID[up.ID] = up
	}
	// Split-DNS: домены, у которых свой апстрим.
	for _, rule := range cfg.DNS.SplitRules {
		if !rule.Enabled || rule.Upstream == "" {
			continue
		}
		up, ok := upstreamByID[rule.Upstream]
		if !ok || !up.Enabled {
			continue
		}
		for _, domain := range rule.Domains {
			domain = strings.Trim(domain, ".")
			if domain == "" {
				continue
			}
			w("  - \"[/%s/]%s\"", domain, dnsproxyUpstream(up))
		}
	}
	for _, up := range cfg.DNS.Upstreams {
		if !up.Enabled {
			continue
		}
		w("  - %q", dnsproxyUpstream(up))
	}

	// Bootstrap разрешает имя самого шифрованного сервера. Без него DoH и DoQ,
	// заданные доменом, не поднимутся вовсе.
	if len(cfg.DNS.Bootstrap) > 0 {
		w("bootstrap:")
		for _, addr := range cfg.DNS.Bootstrap {
			w("  - %q", withDefaultPort(addr, 53))
		}
	}

	if cfg.DNS.CacheSize > 0 {
		w("cache: true")
		// Пользователь задаёт число записей, dnsproxy — размер в байтах.
		w("cache-size: %d", cfg.DNS.CacheSize*128)
	}
	if cfg.DNS.DNSSEC {
		w("dnssec: true")
	}
	if cfg.IPv6.FilterAAAA {
		// AAAA получают пустой ответ.
		w("ipv6-disabled: true")
	}
	if cfg.DNS.RebindProtection {
		w("private-subnets:")
		for _, addr := range privateRanges {
			w("  - %q", addr)
		}
		// Обратные запросы для приватных адресов направляем локальному
		// резолверу, а не наружу: иначе внутренняя адресация утекает
		// публичному DNS. Ключи обязаны идти парой — dnsproxy отказывается
		// стартовать с use-private-rdns без апстрима («private rdns
		// upstreams: no value»), поэтому без dnsmasq не пишем ни того, ни
		// другого.
		if backendLocalDNSNeeded(cfg) {
			w("use-private-rdns: true")
			w("private-rdns-upstream:")
			w("  - \"127.0.0.1:%d\"", dnsmasqLocalPort)
		}
	}
	// ANY используют для усиления в атаках отражением, а полезной нагрузки в
	// нём для клиентов роутера нет.
	w("refuse-any: true")
	if cfg.DNS.QueryLog && !policyBackend {
		w("verbose: true")
		w("output: %q", "/var/log/netos/dns.log")
	}
	if len(cfg.DNS.StaticRecords) > 0 || hasEnabledBlocklists(cfg) {
		w("hosts-file-enabled: true")
		w("hosts-files:")
		if len(cfg.DNS.StaticRecords) > 0 {
			w("  - %q", dnsproxyHostsPath)
		}
		if hasEnabledBlocklists(cfg) {
			w("  - %q", dnsproxyBlocklistPath)
		}
	}
	return b.String()
}

// RenderHosts собирает файл локальных записей. dnsproxy не имеет собственного
// синтаксиса для них и читает обычный hosts, поэтому сюда попадают только
// адресные записи — остальные типы этот формат выразить не может.
func (d *Dnsproxy) RenderHosts(cfg *config.Config) string {
	var b strings.Builder
	fmt.Fprintln(&b, "# Сгенерировано netOS. Правки будут перезаписаны.")
	for _, rec := range cfg.DNS.StaticRecords {
		if rec.Type != "A" {
			continue
		}
		fmt.Fprintf(&b, "%s %s\n", rec.Value, rec.Name)
	}
	return b.String()
}

// dnsproxyUpstream приводит апстрим к схеме, которую понимает dnsproxy.
func dnsproxyUpstream(up config.Upstream) string {
	addr := strings.TrimSpace(up.Address)
	switch up.Type {
	case "dot":
		return ensureScheme(addr, "tls://")
	case "doh":
		return ensureScheme(addr, "https://")
	case "doq":
		return ensureScheme(addr, "quic://")
	default:
		// Обычный DNS: порт обязателен, иначе dnsproxy примет адрес за имя.
		return withDefaultPort(addr, 53)
	}
}

func ensureScheme(addr, scheme string) string {
	if strings.Contains(addr, "://") {
		return addr
	}
	return scheme + addr
}

// withDefaultPort дописывает порт, если пользователь его не указал.
func withDefaultPort(addr string, port int) string {
	if strings.Contains(addr, "://") || strings.Contains(addr, "]") {
		return addr
	}
	if strings.Contains(addr, ":") {
		return addr
	}
	return fmt.Sprintf("%s:%d", addr, port)
}

func (d *Dnsproxy) Apply(ctx context.Context, cfg *config.Config) error {
	return d.ApplyPrepared(ctx, cfg, false)
}

func (d *Dnsproxy) ApplyPrepared(ctx context.Context, cfg *config.Config, forceRestart bool) error {
	if !d.Needed(cfg) {
		if err := removeManagedUnit(ctx, d.Systemd, dnsproxyUnit); err != nil {
			return err
		}
		return removeGenerated(dnsproxyConfPath, dnsproxyHostsPath)
	}

	// dnsproxy ставится подсистемой компонентов, а не apt. Если его выбрали
	// резолвером, но компонент не включили, юнит просто не запустится —
	// объясняем причину здесь, а не оставляем разбираться с журналом systemd.
	if _, err := os.Stat(dnsproxyBinary); err != nil {
		return fmt.Errorf(
			"dnsproxy выбран резолвером, но не установлен: включите компонент dnsproxy в разделе «Компоненты»")
	}

	hosts := []byte(d.RenderHosts(cfg))
	hostsChanged, err := writeManagedFile(dnsproxyHostsPath, hosts, 0o644)
	if err != nil {
		return err
	}

	content := []byte(d.Render(cfg))
	confChanged, err := writeManagedFile(dnsproxyConfPath, content, 0o644)
	if err != nil {
		return err
	}
	changed := hostsChanged || confChanged
	if err := d.ensureUnit(ctx); err != nil {
		return err
	}

	if !forceRestart && !changed && d.Systemd.IsActive(ctx, dnsproxyUnit) {
		return nil
	}
	return d.Systemd.Restart(ctx, dnsproxyUnit)
}

func (d *Dnsproxy) ensureUnit(ctx context.Context) error {
	changed, err := writeManagedFile(filepath.Join(systemdUnitDir, dnsproxyUnit), []byte(dnsproxyUnitContent()), 0o644)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	return d.Systemd.DaemonReload(ctx)
}

func dnsproxyUnitContent() string {
	return `[Unit]
Description=netOS dnsproxy (шифрованный DNS-резолвер)
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=` + dnsproxyBinary + ` --config-path=` + dnsproxyConfPath + `
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`
}

func (d *Dnsproxy) Health(ctx context.Context, cfg *config.Config) error {
	if !d.Needed(cfg) {
		if d.Systemd.IsActive(ctx, dnsproxyUnit) {
			return fmt.Errorf("dnsproxy запущен, хотя не выбран")
		}
		if err := generatedAbsent(dnsproxyConfPath); err != nil {
			return err
		}
		return generatedAbsent(dnsproxyHostsPath)
	}
	if !d.Systemd.IsActive(ctx, dnsproxyUnit) {
		return fmt.Errorf("dnsproxy не запущен")
	}
	if _, err := os.Stat(dnsproxyBinary); err != nil {
		return fmt.Errorf("dnsproxy binary: %w", err)
	}
	if err := managedFileHealth(dnsproxyConfPath, []byte(d.Render(cfg)), 0o644); err != nil {
		return err
	}
	if err := managedFileHealth(dnsproxyHostsPath, []byte(d.RenderHosts(cfg)), 0o644); err != nil {
		return err
	}
	return managedFileHealth(filepath.Join(systemdUnitDir, dnsproxyUnit), []byte(dnsproxyUnitContent()), 0o644)
}
