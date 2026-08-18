package services

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func dnsproxyConfig() *config.Config {
	cfg := resolverConfig()
	cfg.DNS.Provider = "dnsproxy"
	return cfg
}

func TestDnsproxyUpstreamSchemes(t *testing.T) {
	cases := []struct {
		up   config.Upstream
		want string
	}{
		// Без схемы dnsproxy не поймёт, что апстрим шифрованный, и пойдёт
		// открытым текстом — дописываем её сами.
		{config.Upstream{Type: "dot", Address: "1.1.1.1"}, "tls://1.1.1.1"},
		{config.Upstream{Type: "doq", Address: "dns.adguard.com"}, "quic://dns.adguard.com"},
		{config.Upstream{Type: "doh", Address: "https://dns.google/dns-query"}, "https://dns.google/dns-query"},
		// Без порта обычный адрес будет принят за имя.
		{config.Upstream{Type: "plain", Address: "9.9.9.9"}, "9.9.9.9:53"},
		{config.Upstream{Type: "plain", Address: "9.9.9.9:5353"}, "9.9.9.9:5353"},
	}
	for _, c := range cases {
		if got := dnsproxyUpstream(c.up); got != c.want {
			t.Errorf("%s %s → %s, ожидалось %s", c.up.Type, c.up.Address, got, c.want)
		}
	}
}

func TestDnsproxyFiltersAAAA(t *testing.T) {
	cfg := dnsproxyConfig()
	cfg.IPv6.FilterAAAA = true
	out := NewDnsproxy(nil).Render(cfg)
	if !strings.Contains(out, "ipv6-disabled: true") {
		t.Fatalf("фильтр AAAA не включён:\n%s", out)
	}

	cfg.IPv6.FilterAAAA = false
	if strings.Contains(NewDnsproxy(nil).Render(cfg), "ipv6-disabled") {
		t.Fatal("фильтр AAAA включён вопреки настройке")
	}
}

func TestDnsproxyRoutesLocalZoneToDnsmasq(t *testing.T) {
	out := NewDnsproxy(nil).Render(dnsproxyConfig())
	for _, want := range []string{
		"\"[/lan/]127.0.0.1:5354\"",
		"\"[/10.168.192.in-addr.arpa/]127.0.0.1:5354\"",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("нет маршрута локальной зоны %q:\n%s", want, out)
		}
	}
}

func TestDnsproxySplitRuleGetsOwnUpstream(t *testing.T) {
	cfg := dnsproxyConfig()
	cfg.DNS.Upstreams = []config.Upstream{
		{ID: "up-doh", Type: "doh", Address: "https://dns.quad9.net/dns-query", Enabled: true},
	}
	cfg.DNS.SplitRules = []config.DNSSplitRule{
		{ID: "r1", Domains: []string{".corp.example."}, Upstream: "up-doh", Enabled: true},
	}
	out := NewDnsproxy(nil).Render(cfg)
	if !strings.Contains(out, "\"[/corp.example/]https://dns.quad9.net/dns-query\"") {
		t.Fatalf("правило split-DNS собрано неверно:\n%s", out)
	}
}

func TestDnsproxyDisabledSplitUpstreamIsSkipped(t *testing.T) {
	cfg := dnsproxyConfig()
	cfg.DNS.Upstreams = []config.Upstream{
		{ID: "up-off", Type: "doh", Address: "https://off.example/dns-query", Enabled: false},
	}
	cfg.DNS.SplitRules = []config.DNSSplitRule{
		{ID: "r1", Domains: []string{"corp.example"}, Upstream: "up-off", Enabled: true},
	}
	if strings.Contains(NewDnsproxy(nil).Render(cfg), "off.example") {
		t.Fatal("выключенный апстрим попал в конфигурацию")
	}
}

func TestDnsproxyHostsFileHoldsOnlyAddressRecords(t *testing.T) {
	cfg := dnsproxyConfig()
	cfg.DNS.StaticRecords = []config.DNSRecord{
		{Type: "A", Name: "nas.lan", Value: "192.168.10.20"},
		{Type: "CNAME", Name: "files.lan", Value: "nas.lan"},
	}
	hosts := NewDnsproxy(nil).RenderHosts(cfg)
	if !strings.Contains(hosts, "192.168.10.20 nas.lan") {
		t.Fatalf("нет адресной записи:\n%s", hosts)
	}
	// Формат hosts не выражает CNAME — молча писать туда мусор нельзя.
	if strings.Contains(hosts, "files.lan") {
		t.Fatalf("CNAME попал в hosts-файл:\n%s", hosts)
	}
	if !strings.Contains(NewDnsproxy(nil).Render(cfg), "hosts-file-enabled: true") {
		t.Fatal("hosts-файл сгенерирован, но не подключён")
	}
}

func TestDnsproxyListensOnlyOnRouterAddresses(t *testing.T) {
	out := NewDnsproxy(nil).Render(dnsproxyConfig())
	// Проверяем именно блок listen-addrs: подстрокой искать нельзя, 0.0.0.0
	// встречается и внутри приватного диапазона 10.0.0.0/8.
	block, _, ok := strings.Cut(out, "listen-ports:")
	if !ok {
		t.Fatalf("в конфигурации нет портов прослушивания:\n%s", out)
	}
	_, listen, ok := strings.Cut(block, "listen-addrs:")
	if !ok {
		t.Fatalf("в конфигурации нет адресов прослушивания:\n%s", out)
	}
	for _, want := range []string{"\"127.0.0.1\"", "\"192.168.10.1\""} {
		if !strings.Contains(listen, want) {
			t.Fatalf("нет адреса %s:\n%s", want, listen)
		}
	}
	if strings.Contains(listen, "0.0.0.0") {
		t.Fatalf("резолвер слушает на всех адресах, включая аплинк:\n%s", listen)
	}
}

// dnsproxy отказывается стартовать с use-private-rdns без апстрима, поэтому
// ключи обязаны появляться и исчезать вместе.
func TestDnsproxyPrivateRDNSKeysStayPaired(t *testing.T) {
	withLocal := NewDnsproxy(nil).Render(dnsproxyConfig())
	if !strings.Contains(withLocal, "use-private-rdns: true") ||
		!strings.Contains(withLocal, "private-rdns-upstream:") {
		t.Fatalf("при наличии dnsmasq обратные запросы не направлены внутрь:\n%s", withLocal)
	}

	// Без dnsmasq локального резолвера нет — и объявлять приватный rDNS нечем.
	cfg := dnsproxyConfig()
	cfg.DHCP.Enabled = false
	out := NewDnsproxy(nil).Render(cfg)
	if strings.Contains(out, "use-private-rdns") || strings.Contains(out, "private-rdns-upstream") {
		t.Fatalf("объявлен приватный rDNS без апстрима — dnsproxy не запустится:\n%s", out)
	}
}
