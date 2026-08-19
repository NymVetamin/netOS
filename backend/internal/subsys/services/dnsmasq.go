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
	"path/filepath"
	"sort"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

const (
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
	return dhcp || dns
}

// Render собирает конфигурацию dnsmasq целиком.
func (d *Dnsmasq) Render(cfg *config.Config) string {
	serveDHCP := cfg.DHCP.Enabled && cfg.DHCP.Provider == "dnsmasq"
	serveDNS := cfg.DNS.Enabled && cfg.DNS.Provider == "dnsmasq"

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

	switch {
	case serveDNS:
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
		d.renderDHCP(&b, cfg, ifaceByID)
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
	w("domain-needed")     // не пересылать наверх имена без домена
	w("bogus-priv")        // не пересылать обратные запросы для приватных сетей
	w("no-resolv")         // апстримы задаём сами, /etc/resolv.conf не читаем
	w("no-poll")
	w("cache-size=%d", cfg.DNS.CacheSize)

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

	// Апстримы. Порядок в конфиге определяет порядок опроса.
	for _, u := range cfg.DNS.Upstreams {
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
			w("address=/%s/%s", rec.Name, rec.Value)
		case "CNAME":
			w("cname=%s,%s", rec.Name, rec.Value)
		case "TXT":
			w("txt-record=%s,%s", rec.Name, rec.Value)
		case "SRV":
			w("srv-host=%s,%s", rec.Name, rec.Value)
		case "MX":
			w("mx-host=%s,%s", rec.Name, rec.Value)
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

func (d *Dnsmasq) renderDHCP(b *strings.Builder, cfg *config.Config, ifaceByID map[string]string) {
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

		w("interface=%s", iface)
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
	if !d.Needed(cfg) {
		return d.Systemd.Disable(ctx, dnsmasqUnit)
	}

	content := []byte(d.Render(cfg))
	changed := system.FileChanged(dnsmasqConfPath, content)

	if err := system.WriteFileAtomic(dnsmasqConfPath, content, 0o644); err != nil {
		return err
	}
	if err := d.ensureUnit(ctx); err != nil {
		return err
	}

	// Синтаксическую ошибку лучше поймать до перезапуска: иначе демон не
	// поднимется и сеть останется без DHCP.
	if _, err := d.Runner.Run(ctx, "dnsmasq", "--test", "--conf-file="+dnsmasqConfPath); err != nil {
		return fmt.Errorf("проверка конфигурации dnsmasq: %w", err)
	}

	if !changed && d.Systemd.IsActive(ctx, dnsmasqUnit) {
		return nil
	}
	return d.Systemd.Restart(ctx, dnsmasqUnit)
}

// ensureUnit создаёт systemd-юнит, указывающий на сгенерированный конфиг.
// Штатный юнит dnsmasq не трогаем, чтобы удаление netOS ничего не сломало.
func (d *Dnsmasq) ensureUnit(ctx context.Context) error {
	unit := `[Unit]
Description=netOS dnsmasq (DHCP и DNS)
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file=` + dnsmasqConfPath + `
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`
	path := filepath.Join("/etc/systemd/system", dnsmasqUnit)
	if !system.FileChanged(path, []byte(unit)) {
		return nil
	}
	if err := system.WriteFileAtomic(path, []byte(unit), 0o644); err != nil {
		return err
	}
	return d.Systemd.DaemonReload(ctx)
}

func (d *Dnsmasq) Health(ctx context.Context, cfg *config.Config) error {
	if !d.Needed(cfg) {
		return nil
	}
	if !d.Systemd.IsActive(ctx, dnsmasqUnit) {
		return fmt.Errorf("dnsmasq не запущен")
	}
	return nil
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
