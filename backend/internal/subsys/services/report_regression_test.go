package services

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestReportSplitTestOverridesBuiltInZone(t *testing.T) {
	cfg := config.Default()
	cfg.DHCP.Enabled = false
	cfg.DNS.Upstreams = []config.Upstream{{ID: "peer", Enabled: true, Type: "plain", Address: "198.51.100.1"}}
	cfg.DNS.SplitRules = []config.DNSSplitRule{{ID: "split", Enabled: true, Upstream: "peer", Domains: []string{"qa.test"}}}
	out := NewUnbound(nil).Render(cfg)
	if !strings.Contains(out, `local-zone: "qa.test." transparent`) {
		t.Fatal("split hidden by builtin .test zone")
	}
}

func TestSplitDNSUpstreamIsNotAlsoARootResolver(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.Enabled = true
	cfg.DNS.Upstreams = []config.Upstream{
		{ID: "root", Type: "plain", Address: "192.0.2.53", Enabled: true},
		{ID: "split", Type: "plain", Address: "198.51.100.53", Channel: "wg", Enabled: true},
	}
	cfg.DNS.SplitRules = []config.DNSSplitRule{{ID: "rule", Enabled: true, Upstream: "split", Domains: []string{"fixture.test"}}}

	renderedByProvider := map[string]string{}
	for _, provider := range []string{"dnsmasq", "dnsproxy", "unbound"} {
		candidate := *cfg
		candidate.DNS = cfg.DNS
		candidate.DNS.Provider = provider
		switch provider {
		case "dnsmasq":
			renderedByProvider[provider] = NewDnsmasq(nil).Render(&candidate)
		case "dnsproxy":
			renderedByProvider[provider] = NewDnsproxy(nil).Render(&candidate)
		case "unbound":
			renderedByProvider[provider] = NewUnbound(nil).Render(&candidate)
		}
	}
	for name, rendered := range renderedByProvider {
		if strings.Count(rendered, "198.51.100.53") != 1 {
			t.Fatalf("%s also put the split-only resolver in the root pool:\n%s", name, rendered)
		}
		if !strings.Contains(rendered, "192.0.2.53") {
			t.Fatalf("%s lost the normal root resolver:\n%s", name, rendered)
		}
	}
}
