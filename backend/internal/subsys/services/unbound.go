package services

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

var (
	unboundConfPath = "/var/lib/netos/generated/unbound.conf"
	unboundUnit     = "netos-unbound.service"
	// Каталог для root.key: unbound обновляет якорь DNSSEC на месте, поэтому
	// файл живёт в изменяемом состоянии, а не рядом с конфигом.
	unboundAnchorPath = "/var/lib/netos/unbound-root.key"
)

// Unbound владеет процессом unbound.
//
// Когда резолвер — unbound, он занимает порт 53 и держит шифрованные апстримы,
// которых dnsmasq не умеет. Но имена, выданные по DHCP, знает как раз dnsmasq,
// поэтому он остаётся поднятым ради DHCP и локальной зоны на loopback-порту, а
// unbound направляет к нему локальный домен и обратные зоны сегментов. Это и
// есть «связка» из архитектуры: наружу — шифрование, внутрь — локальные имена.
type Unbound struct {
	Runner  system.Runner
	Systemd *system.Systemd
}

func NewUnbound(r system.Runner) *Unbound {
	return &Unbound{Runner: r, Systemd: system.NewSystemd(r)}
}

// Needed сообщает, нужен ли unbound при текущей конфигурации.
func (u *Unbound) Needed(cfg *config.Config) bool {
	return cfg.DNS.Enabled && cfg.DNS.Provider == "unbound"
}

// Render собирает unbound.conf целиком.
func (u *Unbound) Render(cfg *config.Config) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("# Сгенерировано netOS. Правки будут перезаписаны при следующем применении.")
	w("")
	w("server:")
	w("    verbosity: 0")
	w("    do-daemonize: no")
	w("    username: \"\"")
	w("    directory: \"/var/lib/netos\"")
	w("    chroot: \"\"")
	w("    pidfile: \"\"")
	w("    use-syslog: no")
	w("    logfile: \"\"")

	policyBackend := hasKernelDomainPolicies(cfg) && cfg.DNS.Provider == "unbound"
	port := cfg.DNS.Port
	if policyBackend {
		port = policyDNSBackendPort
	}
	w("    port: %d", port)
	w("    do-ip4: yes")
	w("    do-udp: yes")
	w("    do-tcp: yes")
	// IPv6 подавляется на всех уровнях: резолвер не должен ни ходить наружу
	// по IPv6, ни предпочитать его при выборе апстрима.
	if cfg.IPv6.Mode == "off" {
		w("    do-ip6: no")
		w("    prefer-ip6: no")
	} else {
		w("    do-ip6: yes")
	}

	// Слушаем на loopback и на адресе роутера в каждом сегменте. На всех
	// адресах подряд не слушаем: панель и резолвер не должны оказаться
	// открытыми со стороны аплинка.
	w("    interface: 127.0.0.1")
	w("    access-control: 0.0.0.0/0 refuse")
	w("    access-control: 127.0.0.0/8 allow")
	if cfg.IPv6.FilterAAAA {
		// Unbound does not have dnsmasq's filter-AAAA switch. Its supported
		// equivalent is the respip module: tag IPv6 response addresses and
		// turn matching answers into NOERROR/NODATA for every allowed client.
		// Keeping this inside Unbound preserves DNSSEC and encrypted upstreams.
		w("    module-config: \"respip validator iterator\"")
		w("    define-tag: \"netos-filter-aaaa\"")
		renderUnboundAAAAClient(&b, "127.0.0.0/8")
	}
	for _, n := range cfg.Networks {
		if policyBackend {
			break
		}
		if !n.Enabled || n.RouterAddress == "" {
			continue
		}
		w("    interface: %s", addressOf(n.RouterAddress))
		if subnet, err := subnetOf(n.RouterAddress); err == nil {
			w("    access-control: %s allow", subnet)
			if cfg.IPv6.FilterAAAA {
				renderUnboundAAAAClient(&b, subnet)
			}
		}
	}
	if cfg.IPv6.FilterAAAA {
		w("    response-ip-tag: ::/0 \"netos-filter-aaaa\"")
	}

	w("    hide-identity: yes")
	w("    hide-version: yes")
	w("    harden-glue: yes")
	w("    harden-dnssec-stripped: yes")
	w("    harden-referral-path: yes")
	w("    qname-minimisation: yes")
	w("    aggressive-nsec: yes")
	// Форвардинг на dnsmasq по 127.0.0.1 без этого будет молча отброшен.
	w("    do-not-query-localhost: no")

	// Кэш. unbound делит его на кэш сообщений и кэш записей; размер задаётся
	// в байтах, а в конфигурации netOS пользователь указывает число записей —
	// пересчитываем по средней длине ответа.
	msgCache := cfg.DNS.CacheSize * 128
	if msgCache < 65536 {
		msgCache = 65536
	}
	w("    msg-cache-size: %d", msgCache)
	w("    rrset-cache-size: %d", msgCache*2)

	if cfg.DNS.DNSSEC {
		w("    auto-trust-anchor-file: \"%s\"", unboundAnchorPath)
	}
	if cfg.DNS.QueryLog && !policyBackend {
		w("    log-queries: yes")
		w("    log-replies: yes")
	}
	if cfg.DNS.RebindProtection {
		// Ответ из публичного DNS, указывающий внутрь локальной сети, — это
		// либо ошибка, либо атака перепривязкой.
		for _, addr := range privateRanges {
			w("    private-address: %s", addr)
		}
		if cfg.DNS.LocalDomain != "" {
			w("    private-domain: \"%s\"", cfg.DNS.LocalDomain)
		}
	}
	if hasEnabledBlocklists(cfg) {
		w("    include: %q", unboundBlocklistPath)
	}
	// Шифрованным апстримам нужен корневой набор сертификатов, иначе проверка
	// имени сервера DoT провалится.
	w("    tls-cert-bundle: \"/etc/ssl/certs/ca-certificates.crt\"")

	u.renderStaticRecords(&b, cfg)
	u.renderLocalZones(&b, cfg)

	w("")
	u.renderForwardZones(&b, cfg)

	if cfg.DNS.AdvancedOptions != "" {
		w("")
		w("# --- дополнительные директивы пользователя ---")
		w("%s", strings.TrimSpace(cfg.DNS.AdvancedOptions))
	}
	return b.String()
}

func renderUnboundAAAAClient(b *strings.Builder, subnet string) {
	fmt.Fprintf(b, "    access-control-tag: %s \"netos-filter-aaaa\"\n", subnet)
	fmt.Fprintf(b, "    access-control-tag-action: %s netos-filter-aaaa always_nodata\n", subnet)
}

// privateRanges — диапазоны, которые публичный DNS возвращать не должен.
var privateRanges = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"127.0.0.0/8",
}

func (u *Unbound) renderStaticRecords(b *strings.Builder, cfg *config.Config) {
	w := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
	if len(cfg.DNS.StaticRecords) == 0 {
		return
	}
	w("")
	w("    # --- локальные записи ---")
	for _, rec := range cfg.DNS.StaticRecords {
		switch rec.Type {
		case "A":
			w("    local-data: \"%s. A %s\"", rec.Name, rec.Value)
			// Обратная запись бесплатна и делает вывод traceroute и логов
			// читаемым, поэтому добавляем её сразу.
			w("    local-data-ptr: \"%s %s\"", rec.Value, rec.Name)
		case "CNAME":
			w("    local-data: \"%s. CNAME %s.\"", rec.Name, strings.TrimSuffix(rec.Value, "."))
		case "TXT":
			// Unbound explicitly requires single quotes around local-data that
			// contains TXT's double-quoted character string.
			escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `'`, `\'`).Replace(rec.Value)
			w("    local-data: '%s. TXT \"%s\"'", rec.Name, escaped)
		case "SRV":
			w("    local-data: \"%s. SRV %s\"", rec.Name, rec.Value)
		case "MX":
			w("    local-data: \"%s. MX %s\"", rec.Name, rec.Value)
		}
	}
}

// renderLocalZones снимает проверку DNSSEC с зон, которых нет в публичном
// дереве: локальный домен и обратные зоны сегментов подписаны быть не могут, и
// без этого их ответы отбрасывались бы как поддельные.
func (u *Unbound) renderLocalZones(b *strings.Builder, cfg *config.Config) {
	if !cfg.DNS.DNSSEC {
		return
	}
	w := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
	zones := localZones(cfg)
	if len(zones) == 0 {
		return
	}
	w("")
	w("    # --- зоны вне публичного дерева DNSSEC ---")
	for _, zone := range zones {
		w("    domain-insecure: \"%s\"", zone)
	}
}

func (u *Unbound) renderForwardZones(b *strings.Builder, cfg *config.Config) {
	w := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }

	// Локальные имена знает dnsmasq: он раздаёт адреса и потому единственный
	// видит, какое имя за каким клиентом закреплено.
	if backendLocalDNSNeeded(cfg) {
		for _, zone := range localZones(cfg) {
			w("forward-zone:")
			w("    name: \"%s\"", zone)
			w("    forward-addr: 127.0.0.1@%d", dnsmasqLocalPort)
			w("")
		}
	}

	upstreamByID := map[string]config.Upstream{}
	for _, up := range cfg.DNS.Upstreams {
		upstreamByID[up.ID] = up
	}

	// Split-DNS: перечисленные домены уходят в отдельный апстрим.
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
			w("forward-zone:")
			w("    name: \"%s\"", domain)
			if up.Type == "dot" {
				w("    forward-tls-upstream: yes")
			}
			w("    forward-addr: %s", unboundUpstream(up))
			w("")
		}
	}

	// Корневая зона. Без единого апстрима unbound работает рекурсором и ходит
	// к корневым серверам сам — это рабочий режим, а не ошибка, поэтому пустой
	// forward-zone просто не пишем.
	var roots []config.Upstream
	tls := false
	for _, up := range cfg.DNS.Upstreams {
		if !up.Enabled {
			continue
		}
		roots = append(roots, up)
		if up.Type == "dot" {
			tls = true
		}
	}
	if len(roots) == 0 {
		return
	}
	w("forward-zone:")
	w("    name: \".\"")
	if tls {
		w("    forward-tls-upstream: yes")
	}
	for _, up := range roots {
		w("    forward-addr: %s", unboundUpstream(up))
	}
}

// unboundUpstream приводит апстрим к синтаксису unbound: адрес@порт#имя, где
// имя обязательно для DoT — по нему проверяется сертификат сервера.
func unboundUpstream(up config.Upstream) string {
	addr := strings.TrimSpace(up.Address)
	if up.Type != "dot" {
		return addr
	}
	// Пользователь мог ввести и полную форму 1.1.1.1@853#cloudflare-dns.com,
	// и короткую 1.1.1.1#cloudflare-dns.com — порт по умолчанию дописываем.
	if strings.Contains(addr, "@") {
		return addr
	}
	host, name, found := strings.Cut(addr, "#")
	if !found {
		return host + "@853"
	}
	return host + "@853#" + name
}

// localZones перечисляет зоны, которые обслуживаются внутри: локальный домен и
// обратные зоны сегментов.
func localZones(cfg *config.Config) []string {
	var zones []string
	if cfg.DNS.LocalDomain != "" {
		zones = append(zones, cfg.DNS.LocalDomain)
	}
	for _, n := range cfg.Networks {
		if !n.Enabled || n.RouterAddress == "" {
			continue
		}
		if zone, err := reverseZoneOf(n.RouterAddress); err == nil {
			zones = append(zones, zone)
		}
	}
	return zones
}

func (u *Unbound) Apply(ctx context.Context, cfg *config.Config) error {
	return u.ApplyPrepared(ctx, cfg, false)
}

func (u *Unbound) ApplyPrepared(ctx context.Context, cfg *config.Config, forceRestart bool) error {
	if !u.Needed(cfg) {
		if err := u.Systemd.Disable(ctx, unboundUnit); err != nil {
			return err
		}
		return removeGenerated(unboundConfPath)
	}

	content := []byte(u.Render(cfg))
	if cfg.DNS.DNSSEC {
		if err := u.ensureTrustAnchor(ctx); err != nil {
			return err
		}
	}
	if err := validateManagedContent(unboundConfPath, content, 0o644, func(path string) error {
		if _, err := u.Runner.Run(ctx, "unbound-checkconf", path); err != nil {
			return fmt.Errorf("проверка конфигурации unbound: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}
	changed, err := writeManagedFile(unboundConfPath, content, 0o644)
	if err != nil {
		return err
	}
	if err := u.ensureUnit(ctx); err != nil {
		return err
	}

	if !forceRestart && !changed && u.Systemd.IsActive(ctx, unboundUnit) {
		return nil
	}
	return u.Systemd.Restart(ctx, unboundUnit)
}

// ensureTrustAnchor создаёт якорь DNSSEC.
//
// Код возврата unbound-anchor не показателен: 1 означает «якорь обновлён», то
// есть штатный исход. Судим по результату — есть файл или нет. Без него
// unbound-checkconf откажет с невнятным «does not exist», поэтому объясняем
// причину сами.
func (u *Unbound) ensureTrustAnchor(ctx context.Context) error {
	if err := trustAnchorHealth(unboundAnchorPath); err == nil {
		return nil
	}
	info, statErr := os.Lstat(unboundAnchorPath)
	if statErr != nil && !os.IsNotExist(statErr) {
		return statErr
	}
	if statErr == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return fmt.Errorf("якорь DNSSEC %s небезопасен: нужен обычный файл без symlink", unboundAnchorPath)
	}
	_, runErr := u.Runner.Run(ctx, "unbound-anchor", "-a", unboundAnchorPath)
	if err := trustAnchorHealth(unboundAnchorPath); err == nil {
		return nil
	}
	if runErr != nil {
		return fmt.Errorf("якорь DNSSEC не создан (%w); отключите DNSSEC или проверьте доступ в сеть", runErr)
	}
	return fmt.Errorf("якорь DNSSEC не создан: %s не появился", unboundAnchorPath)
}

func trustAnchorHealth(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s не является обычным файлом без symlink", path)
	}
	if info.Size() == 0 {
		return fmt.Errorf("%s пуст", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s доступен для записи группе или другим пользователям: mode %o", path, info.Mode().Perm())
	}
	return nil
}

func (u *Unbound) ensureUnit(ctx context.Context) error {
	changed, err := writeManagedFile(filepath.Join(systemdUnitDir, unboundUnit), []byte(unboundUnitContent()), 0o644)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	return u.Systemd.DaemonReload(ctx)
}

func unboundUnitContent() string {
	return `[Unit]
Description=netOS unbound (DNS-резолвер)
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/unbound -d -c ` + unboundConfPath + `
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`
}

func (u *Unbound) Health(ctx context.Context, cfg *config.Config) error {
	if !u.Needed(cfg) {
		if u.Systemd.IsActive(ctx, unboundUnit) {
			return fmt.Errorf("unbound запущен, хотя не выбран")
		}
		return generatedAbsent(unboundConfPath)
	}
	if !u.Systemd.IsActive(ctx, unboundUnit) {
		return fmt.Errorf("unbound не запущен")
	}
	if err := managedFileHealth(unboundConfPath, []byte(u.Render(cfg)), 0o644); err != nil {
		return err
	}
	if err := managedFileHealth(filepath.Join(systemdUnitDir, unboundUnit), []byte(unboundUnitContent()), 0o644); err != nil {
		return err
	}
	if cfg.DNS.DNSSEC {
		if err := trustAnchorHealth(unboundAnchorPath); err != nil {
			return fmt.Errorf("якорь DNSSEC: %w", err)
		}
	}
	if _, err := u.Runner.Run(ctx, "unbound-checkconf", unboundConfPath); err != nil {
		return fmt.Errorf("проверка активной конфигурации unbound: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------

// subnetOf переводит адрес роутера 192.168.1.1/24 в подсеть 192.168.1.0/24.
func subnetOf(cidr string) (string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", err
	}
	return prefix.Masked().String(), nil
}

// reverseZoneOf строит обратную зону сегмента. Поддерживаются маски, кратные
// байту: только они дают зону, которую можно назвать целиком, а дробить
// /25 на отдельные записи ради обратного резолва не нужно.
func reverseZoneOf(cidr string) (string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", err
	}
	if !prefix.Addr().Is4() {
		return "", fmt.Errorf("обратная зона строится только для IPv4")
	}
	bits := prefix.Bits()
	if bits%8 != 0 || bits == 0 {
		return "", fmt.Errorf("маска %d не кратна байту", bits)
	}
	octets := prefix.Masked().Addr().As4()
	var parts []string
	for i := bits/8 - 1; i >= 0; i-- {
		parts = append(parts, fmt.Sprint(octets[i]))
	}
	return strings.Join(parts, ".") + ".in-addr.arpa", nil
}
