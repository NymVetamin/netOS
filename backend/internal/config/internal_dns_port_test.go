package config

import "testing"

// Подчинённый dnsmasq держит 127.0.0.1:5354, резолвер за фронтендом — 5356:
// совпавший с ними порт DNS или панели оборачивался откатом применения.
func TestValidationRejectsInternalDNSPorts(t *testing.T) {
	for _, port := range []int{5354, 5356} {
		cfg := validationFixture()
		cfg.DHCP.Enabled, cfg.DHCP.Provider = true, "dnsmasq"
		cfg.DNS.Enabled, cfg.DNS.Provider, cfg.DNS.Port = true, "unbound", port
		if !hasErrorAt(cfg.Validate(), "dns.port") {
			t.Errorf("dns.port %d accepted with unbound", port)
		}

		cfg = validationFixture()
		cfg.System.Panel.Port = port
		if !hasErrorAt(cfg.Validate(), "system.panel.port") {
			t.Errorf("system.panel.port %d accepted", port)
		}
	}

	// У dnsmasq-резолвера внутренних служб нет: порт остаётся свободным.
	cfg := validationFixture()
	cfg.DNS.Enabled, cfg.DNS.Provider, cfg.DNS.Port = true, "dnsmasq", 5354
	if hasErrorAt(cfg.Validate(), "dns.port") {
		t.Fatal("dns.port 5354 rejected for dnsmasq resolver")
	}
}
