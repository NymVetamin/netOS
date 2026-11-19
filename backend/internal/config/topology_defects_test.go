package config

import (
	"strings"
	"testing"
)

func problemAt(res *ValidationResult, path string) (Problem, bool) {
	for _, p := range res.Problems {
		if strings.HasPrefix(p.Path, path) {
			return p, true
		}
	}
	return Problem{}, false
}

// Два включённых маршрута с одинаковыми назначением, таблицей и метрикой ядро
// не хранит: второй молча вытесняет первый, панель продолжает показывать оба, а
// проверка после применения расхождения не замечает.
func TestDuplicateStaticRouteIsRejected(t *testing.T) {
	cfg := Default()
	cfg.Routing.Static = []StaticRoute{
		{ID: "r1", Name: "через ISP1", Enabled: true, Destination: "198.18.35.1/32", Gateway: "198.18.39.1"},
		{ID: "r2", Name: "через ISP2", Enabled: true, Destination: "198.18.35.1/32", Gateway: "198.18.34.1"},
	}
	res := cfg.Validate()
	p, ok := problemAt(res, "routing.static[1].destination")
	if !ok || p.Severity != "error" {
		t.Fatalf("конфликт маршрутов пропущен: %+v", res.Problems)
	}
	if !strings.Contains(p.Message, "через ISP1") {
		t.Fatalf("сообщение не называет конфликтующий маршрут: %q", p.Message)
	}
}

// Выключенный маршрут в ядро не попадает и ни с чем конфликтовать не может.
func TestDisabledStaticRouteDoesNotConflict(t *testing.T) {
	cfg := Default()
	cfg.Routing.Static = []StaticRoute{
		{ID: "r1", Enabled: true, Destination: "198.18.35.1/32", Gateway: "198.18.39.1"},
		{ID: "r2", Enabled: false, Destination: "198.18.35.1/32", Gateway: "198.18.34.1"},
	}
	if _, ok := problemAt(cfg.Validate(), "routing.static[1]"); ok {
		t.Fatal("выключенный маршрут объявлен конфликтующим")
	}
}

// VLAN, поднятый над мостом, в который он же и включён, — кольцо. Ядро отвечает
// «Device or resource busy» уже на применении, посреди изменений.
func TestVLANOverBridgeContainingItselfIsRejected(t *testing.T) {
	cfg := Default()
	cfg.Interfaces = []Interface{
		{ID: "phy", Name: "eth1", Type: "physical", Enabled: true},
		{ID: "br", Name: "br2", Type: "bridge", Enabled: true, Members: []string{"vl"}},
		{ID: "vl", Name: "vl935", Type: "vlan", Enabled: true, Parent: "br", VLANID: 935},
	}
	res := cfg.Validate()
	p, ok := problemAt(res, "interfaces[2].parent")
	if !ok || p.Severity != "error" {
		t.Fatalf("кольцо VLAN↔мост пропущено: %+v", res.Problems)
	}
}

// dnsproxy классифицирует приватные сети только для обратных запросов и не
// отбрасывает ответы, указывающие внутрь локальной сети. Молча оставленный
// включённым переключатель обещал бы защиту, которой нет.
func TestDnsproxyRebindProtectionWarns(t *testing.T) {
	cfg := Default()
	cfg.DNS.Enabled, cfg.DNS.Provider, cfg.DNS.RebindProtection = true, "dnsproxy", true
	p, ok := problemAt(cfg.Validate(), "dns.rebind_protection")
	if !ok || p.Severity != "warning" {
		t.Fatalf("о неработающей защите от rebinding не предупредили: %+v", cfg.Validate().Problems)
	}
}

func TestIPv6StaticRouteDefaultMetric(t *testing.T) {
	for _, tc := range []struct {
		name, dest, other, gateway string
		conflict                   bool
	}{
		{"prefix", "2001:db8:10::/64", "2001:db8:10::/64", "", true},
		{"host", "2001:db8::1", "2001:db8::1/128", "", true},
		{"default", "default", "::/0", "2001:db8::1", true},
		{"ipv4", "192.0.2.0/24", "192.0.2.0/24", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			a := StaticRoute{ID: "a", Name: "first", Enabled: true, Destination: tc.dest, Type: "blackhole", Gateway: tc.gateway}
			if tc.gateway != "" {
				a.Type = "unicast"
			}
			b := a
			b.ID, b.Name, b.Destination, b.Metric = "b", "second", tc.other, 1024
			for _, pair := range [][]StaticRoute{{a, b}, {b, a}} {
				c.Routing.Static = pair
				result := c.Validate()
				p, ok := problemAt(result, "routing.static[1].destination")
				if ok != tc.conflict || result.HasErrors() != tc.conflict {
					t.Fatal(result.Problems)
				}
				if ok && (p.Severity != "error" || !strings.Contains(p.Message, "1024") || !strings.Contains(p.Message, pair[0].Name)) {
					t.Fatalf("metric %d: %+v", pair[1].Metric, result.Problems)
				}
			}
			b.Metric = 1025
			c.Routing.Static = []StaticRoute{a, b}
			if r := c.Validate(); r.HasErrors() {
				t.Fatal(r.Problems)
			}
			b.Metric, b.Table = 1024, "local"
			c.Routing.Static[1] = b
			if r := c.Validate(); r.HasErrors() {
				t.Fatal(r.Problems)
			}
			b.Table, b.Enabled = "", false
			c.Routing.Static[1] = b
			if r := c.Validate(); r.HasErrors() {
				t.Fatal(r.Problems)
			}
		})
	}
}
