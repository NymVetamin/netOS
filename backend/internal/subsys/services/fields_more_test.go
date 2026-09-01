package services

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestAllStaticRecordTypesRenderForDnsmasqAndUnbound(t *testing.T) {
	cfg := providerTestConfig()
	cfg.DNS.Enabled = true
	cfg.DNS.StaticRecords = []config.DNSRecord{
		{ID: "a", Type: "A", Name: "host.lan", Value: "192.168.50.9"},
		{ID: "c", Type: "CNAME", Name: "alias.lan", Value: "host.lan"},
		{ID: "t", Type: "TXT", Name: "text.lan", Value: `say "hello"`},
		{ID: "s", Type: "SRV", Name: "_sip._tcp.lan", Value: "10 20 5060 sip.lan"},
		{ID: "m", Type: "MX", Name: "lan", Value: "10 mail.lan"},
	}

	cfg.DNS.Provider = "dnsmasq"
	dnsmasq := NewDnsmasq(nil).Render(cfg)
	for _, want := range []string{
		"address=/host.lan/192.168.50.9",
		"cname=alias.lan,host.lan",
		`txt-record=text.lan,say "hello"`,
		"srv-host=_sip._tcp.lan,sip.lan,5060,10,20",
		"mx-host=lan,mail.lan,10",
	} {
		if !strings.Contains(dnsmasq, want) {
			t.Errorf("dnsmasq missing %q:\n%s", want, dnsmasq)
		}
	}

	cfg.DNS.Provider = "unbound"
	unbound := NewUnbound(nil).Render(cfg)
	for _, want := range []string{
		`local-data: "host.lan. A 192.168.50.9"`,
		`local-data-ptr: "192.168.50.9 host.lan"`,
		`local-data: "alias.lan. CNAME host.lan."`,
		`local-data: 'text.lan. TXT "say \"hello\""'`,
		`local-data: "_sip._tcp.lan. SRV 10 20 5060 sip.lan"`,
		`local-data: "lan. MX 10 mail.lan"`,
	} {
		if !strings.Contains(unbound, want) {
			t.Errorf("unbound missing %q:\n%s", want, unbound)
		}
	}
}

func TestEveryDHCPPoolFieldReachesAllProviderConfigs(t *testing.T) {
	cfg := providerTestConfig()
	pool := &cfg.Networks[0].DHCPPool
	pool.Gateway = "192.168.50.254"
	pool.DNSServers = []string{"192.0.2.53", "198.51.100.53"}
	pool.Domain = "office.lan"
	pool.Options = map[string]string{"66": "pxe.office.lan", "224": "vendor-value"}
	cfg.DHCP.AdvancedOptions = "# advanced-sentinel"

	cfg.DHCP.Provider = "dnsmasq"
	dnsmasqOut := NewDnsmasq(nil).Render(cfg)
	cfg.DHCP.Provider = "isc-dhcp-server"
	iscOut := NewISCDHCP(nil).Render(cfg)
	cfg.DHCP.Provider = "kea"
	keaOut := NewKeaDHCP(nil).Render(cfg)
	checks := []struct {
		name string
		out  string
		want []string
	}{
		{"dnsmasq", dnsmasqOut, []string{"192.168.50.254", "192.0.2.53,198.51.100.53", "office.lan", "pxe.office.lan", "vendor-value", "advanced-sentinel"}},
		{"isc", iscOut, []string{"routers 192.168.50.254", "domain-name-servers 192.0.2.53, 198.51.100.53", `domain-name "office.lan"`, "pxe.office.lan", "vendor-value", "advanced-sentinel"}},
		{"kea", keaOut, []string{"192.168.50.254", "192.0.2.53, 198.51.100.53", "office.lan", "pxe.office.lan", "vendor-value"}},
	}
	for _, check := range checks {
		for _, want := range check.want {
			if !strings.Contains(check.out, want) {
				t.Errorf("%s missing %q:\n%s", check.name, want, check.out)
			}
		}
	}
}
