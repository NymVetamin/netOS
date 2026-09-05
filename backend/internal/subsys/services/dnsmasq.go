// Package services генерирует конфигурации внешних демонов, обслуживающих
// DHCP и DNS.
//
// Тонкость: dnsmasq умеет и DHCP, и DNS одновременно, и пользователь может
// выбрать его для одного из двух, а для второго — другой демон. Поэтому конфиг
// dnsmasq собирается один на обе роли, а подсистемы dhcp и dns обращаются к
// общему координатору. Он идемпотентен: перезапуск случается только если
// содержимое конфига действительно изменилось.
package services

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/policy"
	"github.com/netos-router/netos/internal/system"
)

var (
	dnsmasqConfPath  = "/var/lib/netos/generated/dnsmasq.conf"
	dnsmasqLeasePath = "/var/lib/netos/dnsmasq.leases"
	dnsmasqUnit      = "netos-dnsmasq.service"
	// dnsmasqLocalPort — порт на loopback, куда dnsmasq уходит, когда порт 53
	// занял другой резолвер. Имена клиентов знает только тот, кто раздал им
	// адреса, поэтому dnsmasq продолжает отвечать за локальную зону, а
	// выбранный резолвер направляет её сюда. 5353 не берём: его занимает mDNS.
	dnsmasqLocalPort = 5354
)

// localDNSNeeded сообщает, работает ли dnsmasq подчинённым резолвером
// локальной зоны — то есть DHCP раздаёт он, а порт 53 держит кто-то другой.
func localDNSNeeded(cfg *config.Config) bool {
	return cfg.DHCP.Enabled && cfg.DHCP.Provider == "dnsmasq" &&
		cfg.DNS.Enabled && cfg.DNS.Provider != "dnsmasq"
}

// dnsListenInterfaces перечисляет интерфейсы, на которых резолвер обязан
// принимать запросы: loopback ради самого роутера, интерфейс каждого
// включённого сегмента и интерфейсы серверов VPN — клиент, получивший в
// профиле адрес роутера, вправе рассчитывать, что имена по нему разрешаются.
//
// ocserv сюда не попадает: имя его устройства складывается из настройки и
// номера рабочего процесса, и заранее оно неизвестно.
func dnsListenInterfaces(cfg *config.Config) []string {
	ifaceByID := make(map[string]string, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		ifaceByID[iface.ID] = iface.Name
	}
	seen := map[string]bool{"lo": true}
	var out []string
	add := func(name string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	for _, network := range cfg.Networks {
		if network.Enabled {
			add(ifaceByID[network.Interface])
		}
	}
	for _, server := range cfg.VPNServers {
		if !server.Enabled {
			continue
		}
		switch server.Type {
		case "wireguard":
			add(fmt.Sprintf("wg-srv%d", server.Index))
		case "ikev2":
			add(fmt.Sprintf("xfrm-srv%d", server.Index))
		}
	}
	return out
}

// Dnsmasq владеет процессом dnsmasq.
type Dnsmasq struct {
	Runner  system.Runner
	Systemd *system.Systemd
}

func NewDnsmasq(r system.Runner) *Dnsmasq {
	return &Dnsmasq{Runner: r, Systemd: system.NewSystemd(r)}
}

// Needed сообщает, нужен ли dnsmasq при текущей конфигурации.
func (d *Dnsmasq) Needed(cfg *config.Config) bool {
	dhcp := cfg.DHCP.Enabled && cfg.DHCP.Provider == "dnsmasq"
	dns := cfg.DNS.Enabled && cfg.DNS.Provider == "dnsmasq"
	return dhcp || dns || hasKernelDomainPolicies(cfg)
}

// Render собирает конфигурацию dnsmasq целиком.
func (d *Dnsmasq) Render(cfg *config.Config) string {
	serveDHCP := cfg.DHCP.Enabled && cfg.DHCP.Provider == "dnsmasq"
	serveDNS := cfg.DNS.Enabled && (cfg.DNS.Provider == "dnsmasq" || hasKernelDomainPolicies(cfg))

	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("# Сгенерировано netOS. Правки будут перезаписаны при следующем применении.")
	w("")

	// Общие параметры.
	w("# --- общее ---")
	w("bind-dynamic") // слушать только на нужных интерфейсах, но переживать их появление
	w("user=root")
	w("group=root")
	// Каталог /etc/dnsmasq.d намеренно не подключаем: конфиг должен целиком
	// определяться конфигурацией netOS, иначе применённое состояние перестанет
	// соответствовать тому, что видит администратор в панели.
	w("")

	ifaceByID := map[string]string{}
	for _, i := range cfg.Interfaces {
		ifaceByID[i.ID] = i.Name
	}

	listening := map[string]bool{"lo": true}
	switch {
	case serveDNS:
		for _, iface := range dnsListenInterfaces(cfg) {
			listening[iface] = true
		}
		d.renderDNS(&b, cfg)
	case localDNSNeeded(cfg):
		// Порт 53 держит другой резолвер, но имена клиентов знает dnsmasq:
		// он раздал адреса и единственный видит, какое имя за кем закреплено.
		// Поэтому он отвечает за локальную зону на loopback-порту, а
		// вышестоящий резолвер направляет эту зону сюда.
		d.renderLocalDNS(&b, cfg)
	default:
		// dnsmasq поднят только ради DHCP — DNS-часть надо явно отключить,
		// иначе он займёт порт 53 и подерётся с выбранным резолвером.
		w("port=0")
		w("")
	}

	if serveDHCP {
		d.renderDHCP(&b, cfg, ifaceByID, listening)
	} else {
		w("no-dhcp-interface=")
	}

	return b.String()
}

func (d *Dnsmasq) renderDNS(b *strings.Builder, cfg *config.Config) {
	w := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }

	w("# --- DNS ---")
	w("port=%d", cfg.DNS.Port)
	// Роутеру нужен собственный резолвер: через него он проверяет доступность
	// каналов, разрешает адреса VPN-эндпоинтов и ходит за обновлениями.
	w("interface=lo")
	w("listen-address=127.0.0.1")
	// Слушать сегменты обязательно, а не по желанию: с bind-dynamic dnsmasq
	// принимает запросы только на перечисленных интерфейсах. Раньше их
	// добавлял лишь ForceLocal, а в остальных случаях список интерфейсов
	// случайно приносила DHCP-часть конфига — и связка «DHCP не dnsmasq,
	// резолвер dnsmasq» оставляла клиентов без DNS: демон работал, но слушал
	// один loopback. Unbound и dnsproxy всегда слушают адрес роутера в каждом
	// сегменте, dnsmasq теперь тоже.
	for _, iface := range dnsListenInterfaces(cfg) {
		w("interface=%s", iface)
	}
	w("domain-needed") // не пересылать наверх имена без домена
	w("bogus-priv")    // не пересылать обратные запросы для приватных сетей
	w("no-resolv")     // апстримы задаём сами, /etc/resolv.conf не читаем
	w("no-poll")
	w("cache-size=%d", cfg.DNS.CacheSize)
	domainPolicies := hasKernelDomainPolicies(cfg)
	policyFrontend := domainPolicies && cfg.DNS.Provider != "dnsmasq"
	if domainPolicies {
		w("max-ttl=%d", policy.DomainSetTimeout)
		w("max-cache-ttl=%d", policy.DomainSetTimeout)
	}

	if cfg.DNS.LocalDomain != "" {
		w("local=/%s/", cfg.DNS.LocalDomain)
		w("domain=%s", cfg.DNS.LocalDomain)
		w("expand-hosts")
	}
	if cfg.DNS.RebindProtection {
		w("stop-dns-rebind")
		w("rebind-localhost-ok")
	}
	if cfg.IPv6.FilterAAAA {
		// Клиент, получивший AAAA, попытается пойти по IPv6 мимо каналов.
		w("filter-AAAA")
	}
	if cfg.DNS.QueryLog {
		w("log-queries")
		w("log-facility=/var/log/netos/dns.log")
	}
	if hasEnabledBlocklists(cfg) && cfg.DNS.Provider == "dnsmasq" {
		w("conf-file=%s", dnsmasqBlocklistPath)
	}
	if policyFrontend {
		w("server=127.0.0.1#%d", policyDNSBackendPort)
	}
	if domainPolicies {
		for _, line := range renderDomainPolicyIPSets(cfg) {
			w("%s", line)
		}
	}

	// Апстримы. Порядок в конфиге определяет порядок опроса.
	for _, u := range cfg.DNS.Upstreams {
		if policyFrontend {
			break
		}
		if !u.Enabled {
			continue
		}
		if u.Type != "plain" {
			// DoT/DoH dnsmasq не умеет — такие апстримы обслуживает
			// вышестоящий резолвер, и валидатор об этом уже предупредил.
			continue
		}
		w("server=%s", u.Address)
	}

	// Правила split-DNS: конкретные домены уходят в свой апстрим.
	upstreamByID := map[string]config.Upstream{}
	for _, u := range cfg.DNS.Upstreams {
		upstreamByID[u.ID] = u
	}
	for _, rule := range cfg.DNS.SplitRules {
		if policyFrontend {
			break
		}
		if !rule.Enabled || rule.Upstream == "" {
			continue
		}
		up, ok := upstreamByID[rule.Upstream]
		if !ok || up.Type != "plain" {
			continue
		}
		for _, domain := range rule.Domains {
			w("server=/%s/%s", strings.TrimPrefix(domain, "."), up.Address)
		}
	}

	// Локальные записи.
	for _, rec := range cfg.DNS.StaticRecords {
		switch rec.Type {
		case "A":
			// host-record, а не address=/имя/адрес: цель CNAME dnsmasq ищет
			// только среди host-record, аренд и /etc/hosts. С address= запись
			// отвечала сама, но CNAME на неё возвращал клиенту голый CNAME без
			// адреса, и имя не разрешалось вовсе.
			w("host-record=%s,%s", rec.Name, rec.Value)
		case "CNAME":
			w("cname=%s,%s", rec.Name, rec.Value)
		case "TXT":
			w("txt-record=%s,%s", rec.Name, rec.Value)
		case "SRV":
			// Canonical value is RFC order: priority weight port target.
			// dnsmasq expects target,port,priority,weight.
			fields := strings.Fields(rec.Value)
			if len(fields) == 4 {
				w("srv-host=%s,%s,%s,%s,%s", rec.Name, fields[3], fields[2], fields[0], fields[1])
			}
		case "MX":
			// Canonical value is RFC order: priority target; dnsmasq uses target,priority.
			fields := strings.Fields(rec.Value)
			if len(fields) == 2 {
				w("mx-host=%s,%s,%s", rec.Name, fields[1], fields[0])
			}
		}
	}
	w("")
}

// renderLocalDNS настраивает dnsmasq подчинённым резолвером локальной зоны.
// Наружу он не ходит вовсе: всё, чего нет среди аренд и локальных записей,
// вышестоящий резолвер разрешает сам, и второй путь в интернет ему не нужен.
func (d *Dnsmasq) renderLocalDNS(b *strings.Builder, cfg *config.Config) {
	w := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }

	w("# --- локальная зона (порт 53 держит %s) ---", cfg.DNS.Provider)
	w("port=%d", dnsmasqLocalPort)
	w("interface=lo")
	w("listen-address=127.0.0.1")
	// bind-interfaces здесь не ставим, хотя привязка нужна только к loopback:
	// в общей части конфига уже стоит bind-dynamic, а вместе они несовместимы —
	// dnsmasq отказывается запускаться («cannot set --bind-interfaces and
	// --bind-dynamic»). Проверка dnsmasq --test этого не ловит: конфликт
	// вскрывается на привязке сокетов, то есть уже после успешного применения.
	// bind-dynamic делает то же самое: с interface=lo слушается только loopback.
	w("no-resolv")
	w("no-poll")
	// Пустой список апстримов: на неизвестное имя честно отвечаем отказом,
	// а не идём в интернет в обход выбранного резолвера и его шифрования.
	w("no-hosts")
	if cfg.DNS.LocalDomain != "" {
		w("local=/%s/", cfg.DNS.LocalDomain)
		w("domain=%s", cfg.DNS.LocalDomain)
		w("expand-hosts")
	}
	if cfg.IPv6.FilterAAAA {
		w("filter-AAAA")
	}
	w("")
}

// listening — интерфейсы, уже перечисленные DNS-частью конфига. Повторять их
// незачем: interface= в dnsmasq один на весь процесс, а не на роль.
func (d *Dnsmasq) renderDHCP(b *strings.Builder, cfg *config.Config, ifaceByID map[string]string, listening map[string]bool) {
	w := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }

	w("# --- DHCP ---")
	w("dhcp-leasefile=%s", dnsmasqLeasePath)
	w("dhcp-authoritative") // мы единственный DHCP в этих сетях
	w("no-ping")            // не проверять адрес пингом, ускоряет выдачу

	for _, n := range cfg.Networks {
		if !n.Enabled || !n.DHCPPool.Enabled {
			continue
		}
		iface := ifaceByID[n.Interface]
		if iface == "" {
			continue
		}
		pool := n.DHCPPool

		mask, err := netmaskOf(n.RouterAddress)
		if err != nil {
			continue
		}

		if !listening[iface] {
			w("interface=%s", iface)
			listening[iface] = true
		}
		tag := "net-" + n.ID
		w("dhcp-range=set:%s,%s,%s,%s,%ds", tag, pool.Start, pool.End, mask, pool.LeaseTime)

		gateway := pool.Gateway
		if gateway == "" {
			gateway = addressOf(n.RouterAddress)
		}
		w("dhcp-option=tag:%s,option:router,%s", tag, gateway)

		dns := pool.DNSServers
		if len(dns) == 0 {
			dns = []string{addressOf(n.RouterAddress)}
		}
		w("dhcp-option=tag:%s,option:dns-server,%s", tag, strings.Join(dns, ","))

		if pool.Domain != "" {
			w("dhcp-option=tag:%s,option:domain-name,%s", tag, pool.Domain)
		}

		// Произвольные опции по номерам — для тех случаев, когда клиенту нужно
		// что-то нестандартное (PXE, WPAD, вендорские опции).
		codes := make([]string, 0, len(pool.Options))
		for code := range pool.Options {
			codes = append(codes, code)
		}
		sort.Strings(codes)
		for _, code := range codes {
			w("dhcp-option=tag:%s,%s,%s", tag, code, pool.Options[code])
		}
	}

	// Статические привязки.
	for _, res := range cfg.DHCP.Reservations {
		if !res.Enabled {
			continue
		}
		parts := []string{res.MAC}
		if res.Hostname != "" {
			parts = append(parts, res.Hostname)
		}
		parts = append(parts, res.IP)
		w("dhcp-host=%s", strings.Join(parts, ","))
	}

	// Заблокированным устройствам просто не выдаём адрес — вместе с правилом
	// DROP в файрволле это отрезает их надёжно.
	for _, cl := range cfg.Clients {
		if cl.Blocked && cl.MAC != "" {
			w("dhcp-host=%s,ignore", cl.MAC)
		}
	}

	if cfg.DHCP.AdvancedOptions != "" {
		w("")
		w("# --- дополнительные директивы пользователя ---")
		w("%s", strings.TrimSpace(cfg.DHCP.AdvancedOptions))
	}
	w("")
}

// Apply записывает конфиг и перезапускает демона, только если содержимое
// изменилось: лишний перезапуск сбрасывает кэш DNS и заставляет клиентов
// переспрашивать аренды.
func (d *Dnsmasq) Apply(ctx context.Context, cfg *config.Config) error {
	return d.ApplyPrepared(ctx, cfg, false)
}

func (d *Dnsmasq) ApplyPrepared(ctx context.Context, cfg *config.Config, forceRestart bool) error {
	if !d.Needed(cfg) {
		if err := removeManagedUnit(ctx, d.Systemd, dnsmasqUnit); err != nil {
			return err
		}
		return removeGenerated(dnsmasqConfPath)
	}

	content := []byte(d.Render(cfg))
	if err := validateManagedContent(dnsmasqConfPath, content, 0o644, func(path string) error {
		if _, err := d.Runner.Run(ctx, "dnsmasq", "--test", "--conf-file="+path); err != nil {
			return fmt.Errorf("проверка конфигурации dnsmasq: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}
	changed, err := writeManagedFile(dnsmasqConfPath, content, 0o644)
	if err != nil {
		return err
	}
	if err := os.Chmod(dnsmasqLeasePath, 0o600); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("права файла аренд dnsmasq: %w", err)
	}
	if err := d.ensureUnit(ctx); err != nil {
		return err
	}

	if !forceRestart && !changed && d.Systemd.IsActive(ctx, dnsmasqUnit) {
		return nil
	}
	return d.Systemd.Restart(ctx, dnsmasqUnit)
}

// ensureUnit создаёт systemd-юнит, указывающий на сгенерированный конфиг.
// Штатный юнит dnsmasq не трогаем, чтобы удаление netOS ничего не сломало.
func (d *Dnsmasq) ensureUnit(ctx context.Context) error {
	changed, err := writeManagedFile(filepath.Join(systemdUnitDir, dnsmasqUnit), []byte(dnsmasqUnitContent()), 0o644)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	return d.Systemd.DaemonReload(ctx)
}

func dnsmasqUnitContent() string {
	return `[Unit]
Description=netOS dnsmasq (DHCP и DNS)
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file=` + dnsmasqConfPath + `
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=2
UMask=0077

[Install]
WantedBy=multi-user.target
`
}

func (d *Dnsmasq) Health(ctx context.Context, cfg *config.Config) error {
	if !d.Needed(cfg) {
		if d.Systemd.IsActive(ctx, dnsmasqUnit) {
			return fmt.Errorf("dnsmasq запущен, хотя не выбран")
		}
		return generatedAbsent(dnsmasqConfPath)
	}
	if !d.Systemd.IsActive(ctx, dnsmasqUnit) {
		return fmt.Errorf("dnsmasq не запущен")
	}
	if err := managedFileHealth(dnsmasqConfPath, []byte(d.Render(cfg)), 0o644); err != nil {
		return err
	}
	if err := managedFileModeHealth(dnsmasqLeasePath, 0o600, false); err != nil {
		return err
	}
	return managedFileHealth(filepath.Join(systemdUnitDir, dnsmasqUnit), []byte(dnsmasqUnitContent()), 0o644)
}

// LeasePath отдаёт путь к файлу аренд, чтобы панель могла их показывать.
func (d *Dnsmasq) LeasePath() string { return dnsmasqLeasePath }

// ---------------------------------------------------------------------------

func addressOf(cidr string) string {
	if i := strings.IndexByte(cidr, '/'); i >= 0 {
		return cidr[:i]
	}
	return cidr
}

// netmaskOf переводит 192.168.1.1/24 в 255.255.255.0 — dnsmasq хочет маску
// в развёрнутом виде.
func netmaskOf(cidr string) (string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", err
	}
	bits := prefix.Bits()
	if bits < 0 || bits > 32 {
		return "", fmt.Errorf("некорректная длина префикса")
	}
	mask := uint32(0xffffffff) << (32 - bits)
	if bits == 0 {
		mask = 0
	}
	return fmt.Sprintf("%d.%d.%d.%d", mask>>24&0xff, mask>>16&0xff, mask>>8&0xff, mask&0xff), nil
}
