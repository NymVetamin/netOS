package services

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

// resolverConfig — конфигурация, в которой unbound держит порт 53, а dnsmasq
// раздаёт адреса: та самая связка, ради которой добавлен провайдер.
func resolverConfig() *config.Config {
	cfg := config.Default()
	cfg.DNS.Enabled = true
	cfg.DNS.Provider = "unbound"
	cfg.DHCP.Enabled = true
	cfg.DHCP.Provider = "dnsmasq"
	cfg.Interfaces = []config.Interface{{ID: "if-lan", Name: "eth1"}}
	cfg.Networks = []config.Network{{
		ID: "lan", Name: "LAN", Interface: "if-lan",
		RouterAddress: "192.168.10.1/24", Enabled: true,
	}}
	return cfg
}

func TestUnboundListensOnlyOnRouterAddresses(t *testing.T) {
	out := NewUnbound(nil).Render(resolverConfig())
	for _, want := range []string{
		"interface: 127.0.0.1",
		"interface: 192.168.10.1",
		"access-control: 0.0.0.0/0 refuse",
		"access-control: 192.168.10.0/24 allow",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("нет строки %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "interface: 0.0.0.0") {
		t.Fatalf("резолвер слушает на всех адресах, включая аплинк:\n%s", out)
	}
}

func TestUnboundForwardsLocalZonesToDnsmasq(t *testing.T) {
	out := NewUnbound(nil).Render(resolverConfig())
	// Имена клиентов знает только тот, кто раздал им адреса.
	for _, want := range []string{
		"name: \"lan\"",
		"name: \"10.168.192.in-addr.arpa\"",
		"forward-addr: 127.0.0.1@5354",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("локальная зона не направлена в dnsmasq (%q):\n%s", want, out)
		}
	}
}

func TestUnboundDoTUpstreamCarriesPortAndName(t *testing.T) {
	cfg := resolverConfig()
	cfg.DNS.Upstreams = []config.Upstream{
		{ID: "up-dot", Type: "dot", Address: "1.1.1.1#cloudflare-dns.com", Enabled: true},
	}
	out := NewUnbound(nil).Render(cfg)
	if !strings.Contains(out, "forward-tls-upstream: yes") {
		t.Fatalf("DoT не включён:\n%s", out)
	}
	// Без порта unbound пойдёт на 53 открытым текстом, без имени — не проверит
	// сертификат. Обе части обязательны.
	if !strings.Contains(out, "forward-addr: 1.1.1.1@853#cloudflare-dns.com") {
		t.Fatalf("апстрим DoT собран неверно:\n%s", out)
	}
}

func TestUnboundWithoutUpstreamsStaysRecursive(t *testing.T) {
	cfg := resolverConfig()
	cfg.DNS.Upstreams = nil
	out := NewUnbound(nil).Render(cfg)
	if strings.Contains(out, "name: \".\"") {
		t.Fatalf("пустая корневая forward-zone вместо рекурсии:\n%s", out)
	}
}

func TestUnboundMarksLocalZonesInsecureUnderDNSSEC(t *testing.T) {
	cfg := resolverConfig()
	cfg.DNS.DNSSEC = true
	out := NewUnbound(nil).Render(cfg)
	// Локальная зона не подписана; без domain-insecure её ответы отбрасываются
	// как поддельные, и локальные имена перестают резолвиться вовсе.
	for _, want := range []string{
		"domain-insecure: \"lan\"",
		"domain-insecure: \"10.168.192.in-addr.arpa\"",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("нет %q:\n%s", want, out)
		}
	}
}

func TestDnsmasqServesLocalZoneWhenAnotherResolverOwnsPort53(t *testing.T) {
	out := NewDnsmasq(nil).Render(resolverConfig())
	if strings.Contains(out, "port=0") {
		t.Fatalf("dnsmasq отключил DNS и локальные имена потеряны:\n%s", out)
	}
	for _, want := range []string{"port=5354", "listen-address=127.0.0.1", "local=/lan/"} {
		if !strings.Contains(out, want) {
			t.Fatalf("нет строки %q:\n%s", want, out)
		}
	}
	// Второй путь наружу в обход шифрованного резолвера недопустим.
	if strings.Contains(out, "\nserver=") {
		t.Fatalf("подчинённый dnsmasq ходит в интернет сам:\n%s", out)
	}
}

// TestDnsmasqNeverMixesBindModes закрывает ошибку, из-за которой dnsmasq не
// поднимался вовсе: подчинённый резолвер добавлял bind-interfaces к общему
// bind-dynamic, а вместе они запрещены («cannot set --bind-interfaces and
// --bind-dynamic»). Ловится только здесь: dnsmasq --test конфликт пропускает,
// он вскрывается на привязке сокетов, уже после успешного применения.
func TestDnsmasqNeverMixesBindModes(t *testing.T) {
	cases := map[string]*config.Config{
		"подчинённый резолвер": resolverConfig(),
		"dnsmasq на 53":        dnsmasqOwnsDNSConfig(),
		"только DHCP":          dhcpOnlyConfig(),
	}
	for name, cfg := range cases {
		out := NewDnsmasq(nil).Render(cfg)
		if strings.Contains(out, "bind-interfaces") && strings.Contains(out, "bind-dynamic") {
			t.Fatalf("%s: обе привязки сразу, dnsmasq не запустится:\n%s", name, out)
		}
	}
}

func dnsmasqOwnsDNSConfig() *config.Config {
	cfg := resolverConfig()
	cfg.DNS.Provider = "dnsmasq"
	return cfg
}

func dhcpOnlyConfig() *config.Config {
	cfg := resolverConfig()
	cfg.DNS.Enabled = false
	return cfg
}

func TestDnsmasqStaysSilentWhenItOnlyServesDHCP(t *testing.T) {
	cfg := resolverConfig()
	cfg.DNS.Enabled = false
	out := NewDnsmasq(nil).Render(cfg)
	if !strings.Contains(out, "port=0") {
		t.Fatalf("резолвера нет вовсе, но dnsmasq занял порт:\n%s", out)
	}
}

func TestReverseZoneRequiresByteAlignedMask(t *testing.T) {
	if _, err := reverseZoneOf("192.168.10.1/25"); err == nil {
		t.Fatal("обратная зона построена для маски, не кратной байту")
	}
	zone, err := reverseZoneOf("10.0.0.1/8")
	if err != nil {
		t.Fatal(err)
	}
	if zone != "10.in-addr.arpa" {
		t.Fatalf("неверная обратная зона: %s", zone)
	}
}

func TestUnboundFiltersAAAAForEveryAllowedClient(t *testing.T) {
	cfg := resolverConfig()
	cfg.IPv6.FilterAAAA = true
	out := NewUnbound(nil).Render(cfg)
	for _, want := range []string{
		`module-config: "respip validator iterator"`,
		`define-tag: "netos-filter-aaaa"`,
		`access-control-tag: 127.0.0.0/8 "netos-filter-aaaa"`,
		`access-control-tag-action: 127.0.0.0/8 netos-filter-aaaa always_nodata`,
		`access-control-tag: 192.168.10.0/24 "netos-filter-aaaa"`,
		`access-control-tag-action: 192.168.10.0/24 netos-filter-aaaa always_nodata`,
		`response-ip-tag: ::/0 "netos-filter-aaaa"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("нет директивы %q:\n%s", want, out)
		}
	}
	for _, problem := range cfg.Validate().Problems {
		if problem.Path == "ipv6.filter_aaaa" {
			t.Fatalf("рабочий фильтр Unbound всё ещё отмечен как ограничение: %+v", problem)
		}
	}

	cfg.IPv6.FilterAAAA = false
	out = NewUnbound(nil).Render(cfg)
	if strings.Contains(out, "netos-filter-aaaa") || strings.Contains(out, "module-config: \"respip") {
		t.Fatalf("фильтр AAAA остался в выключенной конфигурации:\n%s", out)
	}
}
