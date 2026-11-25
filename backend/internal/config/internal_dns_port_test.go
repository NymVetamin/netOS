package config

import "testing"

// Подчинённый dnsmasq держит 127.0.0.1:5354, резолвер за фронтендом — 5356:
// совпавший с ними порт DNS, панели или SOCKS оборачивался откатом применения.
// Но запрещать их всегда нельзя: ошибка валидации останавливает netosd при
// старте, и рабочая прежде конфигурация с панелью на 5354 после обновления
// оставляла администратора без панели.
func TestValidationRejectsInternalDNSPortsOnlyWhileBusy(t *testing.T) {
	localZone := func(cfg *Config) { // dnsmasq раздаёт адреса, unbound держит DNS: 5354 занят
		cfg.DHCP.Enabled, cfg.DHCP.Provider = true, "dnsmasq"
		cfg.DNS.Enabled, cfg.DNS.Provider = true, "unbound"
	}
	frontend := func(cfg *Config) { // l2tp-сервер требует фронтенд dnsmasq: 5356 занят
		cfg.DNS.Enabled, cfg.DNS.Provider = true, "unbound"
		cfg.VPNServers = append(cfg.VPNServers, VPNServer{ID: "l2", Type: "l2tp", Enabled: true})
	}
	disabledDNS := func(cfg *Config) { cfg.DNS.Enabled = false }
	cases := []struct {
		name  string
		setup func(*Config)
		port  int
		busy  bool
	}{
		{"5354 local zone", localZone, LocalDNSPort, true},
		{"5356 frontend backend", frontend, PolicyDNSBackendPort, true},
		{"5354 DNS off", disabledDNS, LocalDNSPort, false},
		{"5356 DNS off", disabledDNS, PolicyDNSBackendPort, false},
		{"5356 without frontend", localZone, PolicyDNSBackendPort, false},
		// С фронтендом локальную зону обслуживает он сам, 5354 свободен.
		{"5354 with frontend", func(cfg *Config) { localZone(cfg); frontend(cfg) }, LocalDNSPort, false},
	}
	for _, tc := range cases {
		cfg := validationFixture()
		tc.setup(cfg)
		cfg.System.Panel.Port = tc.port
		if got := hasErrorAt(cfg.Validate(), "system.panel.port"); got != tc.busy {
			t.Errorf("%s: panel port rejected=%v, want %v", tc.name, got, tc.busy)
		}

		cfg = validationFixture()
		tc.setup(cfg)
		cfg.Socks.Enabled, cfg.Socks.Port = true, tc.port
		if got := hasErrorAt(cfg.Validate(), "socks.port"); got != tc.busy {
			t.Errorf("%s: socks port rejected=%v, want %v", tc.name, got, tc.busy)
		}

		cfg = validationFixture()
		tc.setup(cfg)
		if cfg.DNS.Enabled {
			cfg.DNS.Port = tc.port
			if got := hasErrorAt(cfg.Validate(), "dns.port"); got != tc.busy {
				t.Errorf("%s: dns port rejected=%v, want %v", tc.name, got, tc.busy)
			}
		}
	}

	// У dnsmasq-резолвера внутренних служб нет: порт остаётся свободным.
	cfg := validationFixture()
	cfg.DNS.Enabled, cfg.DNS.Provider, cfg.DNS.Port = true, "dnsmasq", LocalDNSPort
	if hasErrorAt(cfg.Validate(), "dns.port") {
		t.Fatal("dns.port 5354 rejected for dnsmasq resolver")
	}
}
