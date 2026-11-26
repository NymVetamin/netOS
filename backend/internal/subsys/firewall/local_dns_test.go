package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func buildIPv6(cfg *config.Config) string {
	b := builder{localDNS: cfg.UsesLocalDNSPort()}
	return b.buildIPv6(cfg)
}

func TestLocalDNSStopFailurePreservesFirewall(t *testing.T) {
	cfg := ipv6PassthroughConfig()
	cfg.DHCP.Enabled, cfg.DHCP.Provider = true, "dnsmasq"
	cfg.DNS.Enabled, cfg.DNS.Provider = true, "unbound"
	old, _ := Build(cfg)
	runner := cleanFirewallRunner(old)
	runner.runErrors["systemctl"] = errors.New("cannot stop")
	cfg.DNS.Provider = "dnsmasq"
	if err := New(runner, t.TempDir()).Apply(context.Background(), cfg); err == nil {
		t.Fatal("firewall released the internal port before the listener stopped")
	}
	for _, call := range runner.calls {
		if strings.HasSuffix(call.name, "-restore") && len(call.args) == 0 {
			t.Fatal("live firewall changed after stop failure")
		}
	}
}

func TestLocalDNSAccessFollowsResolverRole(t *testing.T) {
	cfg := ipv6PassthroughConfig()
	cfg.DHCP.Enabled, cfg.DHCP.Provider = true, "dnsmasq"
	cfg.DNS.Enabled = true
	for _, firewall := range []bool{false, true} {
		cfg.Firewall.Enabled = firewall
		for _, resolver := range []string{"unbound", "dnsmasq", "unbound"} {
			cfg.DNS.Provider = resolver
			rules, err := Build(cfg)
			if err != nil {
				t.Fatal(err)
			}
			for _, family := range []string{rules.IPv4, rules.IPv6} {
				filter := ipv6FilterTable(t, family)
				for _, proto := range []string{"tcp", "udp"} {
					drop := "-A INPUT ! -i lo -p " + proto + " --dport 5354 -j NETOS-LOCAL-DNS"
					index := strings.Index(filter, drop)
					if (index >= 0) != (resolver == "unbound") {
						t.Fatalf("firewall=%v resolver=%s: missing or stale %s", firewall, resolver, drop)
					}
					if accept := strings.Index(filter, " -j ACCEPT"); index >= 0 && accept >= 0 && accept < index {
						t.Fatalf("accept before %s", drop)
					}
				}
			}
		}
	}
}
