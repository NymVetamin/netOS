package services

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestSplitOnlyWarningPreservesDNSRouting(t *testing.T) {
	c := config.Default()
	c.Components = append(c.Components, config.Component{ID: "dnsmasq", Installed: true})
	c.DNS.Enabled, c.DNS.Provider = true, "dnsmasq"
	c.DNS.Upstreams = []config.Upstream{{ID: "split", Type: "plain", Address: "192.0.2.53", Enabled: true}}
	c.DNS.SplitRules = []config.DNSSplitRule{{ID: "rule", Enabled: true, Domains: []string{"internal.example"}, Upstream: "split"}}
	for repeat := 0; repeat < 2; repeat++ {
		r := c.Validate()
		warned := false
		for _, p := range r.Problems {
			warned = warned || p.Path == "dns.upstreams" && p.Severity == "warning"
		}
		if r.HasErrors() || !warned {
			t.Fatalf("expected warning only: %+v", r.Problems)
		}
		rendered := NewDnsmasq(nil).Render(c)
		if !strings.Contains(rendered, "no-resolv\n") || !strings.Contains(rendered, "server=/internal.example/192.0.2.53\n") || strings.Contains(rendered, "server=192.0.2.53\n") {
			t.Fatalf("dedicated upstream routing changed: %s", rendered)
		}
	}
	c.DNS.Upstreams = append(c.DNS.Upstreams, config.Upstream{ID: "root", Type: "plain", Address: "192.0.2.54", Enabled: true})
	for _, p := range c.Validate().Problems {
		if p.Path == "dns.upstreams" {
			t.Fatal(p)
		}
	}
	if !strings.Contains(NewDnsmasq(nil).Render(c), "server=192.0.2.54\n") {
		t.Fatal("new root upstream not rendered")
	}
}
