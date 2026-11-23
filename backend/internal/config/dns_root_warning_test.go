package config

import (
	"fmt"
	"testing"
)

func TestDNSRootUpstreamWarning(t *testing.T) {
	for _, provider := range []string{"dnsmasq", "dnsproxy", "unbound"} {
		for _, mode := range []string{"split-only", "root-and-split", "split-disabled", "empty-domains", "duplicate-use", "dns-off", "no-upstreams", "all-disabled"} {
			t.Run(provider+"/"+mode, func(t *testing.T) {
				c := Default()
				c.DNS.Enabled, c.DNS.Provider = true, provider
				c.DNS.Upstreams = []Upstream{{ID: "one", Type: "plain", Address: "192.0.2.53", Enabled: true}}
				c.DNS.SplitRules = []DNSSplitRule{{ID: "split", Enabled: true, Domains: []string{"internal.example"}, Upstream: "one"}}
				want := provider != "unbound"
				switch mode {
				case "root-and-split":
					c.DNS.Upstreams = append(c.DNS.Upstreams, Upstream{ID: "root", Type: "plain", Address: "192.0.2.54", Enabled: true})
					want = false
				case "split-disabled":
					c.DNS.SplitRules[0].Enabled = false
					want = false
				case "empty-domains":
					c.DNS.SplitRules[0].Domains = nil
					want = false
				case "duplicate-use":
					c.DNS.SplitRules = append(c.DNS.SplitRules, DNSSplitRule{ID: "split2", Enabled: true, Domains: []string{"second.example"}, Upstream: "one"})
				case "dns-off":
					c.DNS.Enabled = false
					want = false
				case "no-upstreams":
					c.DNS.Upstreams, c.DNS.SplitRules = nil, nil
				case "all-disabled":
					c.DNS.Upstreams[0].Enabled = false
					c.DNS.SplitRules = nil
				}
				check := func(want bool) {
					t.Helper()
					var r ValidationResult
					c.validateDNS(&r)
					count := 0
					for _, p := range r.Problems {
						if p.Path == "dns.upstreams" && p.Severity == "warning" {
							count++
						}
					}
					if (count == 1) != want || count > 1 {
						t.Fatalf("root warning count=%d want=%t: %+v", count, want, r.Problems)
					}
					if mode != "empty-domains" && r.HasErrors() {
						t.Fatalf("warning must not reject configuration: %+v", r.Problems)
					}
				}
				check(want)
				check(want)
				c.DNS.Upstreams = append(c.DNS.Upstreams, Upstream{ID: "fresh-root", Type: "plain", Address: "192.0.2.55", Enabled: true})
				check(false)
			})
		}
	}
}

func BenchmarkValidateDNSRootWarning(b *testing.B) {
	for _, n := range []int{8, 1024} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			c := Default()
			c.DNS.Enabled = true
			c.DNS.Provider = "dnsmasq"
			c.Components = append(c.Components, Component{ID: "dnsmasq", Installed: true})
			c.DNS.Upstreams = nil
			for i := 0; i < n; i++ {
				id := fmt.Sprintf("up%d", i)
				c.DNS.Upstreams = append(c.DNS.Upstreams, Upstream{ID: id, Type: "plain", Address: "192.0.2.53", Enabled: true})
				c.DNS.SplitRules = append(c.DNS.SplitRules, DNSSplitRule{ID: id, Enabled: true, Domains: []string{"internal.example"}, Upstream: id})
			}
			b.ReportAllocs()
			for b.Loop() {
				if r := c.Validate(); r.HasErrors() {
					b.Fatal(r.Problems)
				}
			}
		})
	}
}
