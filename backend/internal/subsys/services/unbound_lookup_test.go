package services

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func previousLocalZoneLines(cfg *config.Config) string {
	var zones []string
	if backendLocalDNSNeeded(cfg) {
		zones = localZones(cfg)
	}
	for _, rule := range cfg.DNS.SplitRules {
		if !rule.Enabled {
			continue
		}
		for _, up := range cfg.DNS.Upstreams {
			if up.ID == rule.Upstream && up.Enabled {
				zones = append(zones, rule.Domains...)
				break
			}
		}
	}
	var out strings.Builder
	seen := map[string]bool{}
	for _, zone := range zones {
		zone = strings.ToLower(strings.Trim(zone, "."))
		if zone != "" && !seen[zone] {
			fmt.Fprintf(&out, "    local-zone: %q transparent\n", zone+".")
			seen[zone] = true
		}
	}
	return out.String()
}

func TestUnboundLookupPreservesLocalZones(t *testing.T) {
	c := config.Default()
	c.DNS.Provider = "unbound"
	c.DNS.Enabled = true
	c.DNS.Upstreams = []config.Upstream{{ID: "dup", Enabled: true, Type: "plain", Address: "192.0.2.1"}, {ID: "dup", Enabled: false, Type: "plain", Address: "192.0.2.2"}, {ID: "off", Enabled: false}, {ID: "", Enabled: true, Type: "plain", Address: "192.0.2.3"}}
	c.DNS.SplitRules = []config.DNSSplitRule{
		{ID: "a", Enabled: true, Upstream: "dup", Domains: []string{".TEST.", "test", "", "...", "Mixed.example"}},
		{ID: "b", Enabled: true, Upstream: "off", Domains: []string{"disabled.example"}},
		{ID: "c", Enabled: true, Upstream: "missing", Domains: []string{"missing.example"}},
		{ID: "d", Enabled: false, Upstream: "dup", Domains: []string{"disabled-rule.example"}},
		{ID: "e", Enabled: true, Upstream: "", Domains: []string{"empty-id.example"}},
	}
	for shift := 0; shift < len(c.DNS.Upstreams); shift++ {
		for repeat := 0; repeat < 2; repeat++ {
			full := NewUnbound(nil).Render(c)
			var got strings.Builder
			for _, line := range strings.Split(full, "\n") {
				if strings.HasPrefix(line, "    local-zone:") {
					got.WriteString(line + "\n")
				}
			}
			if want := previousLocalZoneLines(c); got.String() != want {
				t.Fatalf("got %q want %q", got.String(), want)
			}
			var last config.Upstream
			for _, up := range c.DNS.Upstreams {
				if up.ID == "dup" {
					last = up
				}
			}
			if strings.Contains(full, "    forward-addr: "+last.Address+"\n") != last.Enabled {
				t.Fatal("forward last-ID behavior changed")
			}
		}
		c.DNS.Upstreams = append(c.DNS.Upstreams[1:], c.DNS.Upstreams[0])
	}
	c.DNS.Upstreams = nil
	if full := NewUnbound(nil).Render(c); strings.Contains(full, "test.\" transparent") || strings.Contains(full, "forward-addr: 192.0.2.") {
		t.Fatal("stale upstream lookup")
	}
}

func BenchmarkUnboundLookupRender(b *testing.B) {
	for _, n := range []int{16, 2048} {
		for _, last := range []bool{false, true} {
			b.Run(fmt.Sprintf("%d/last=%t", n, last), func(b *testing.B) {
				// TestMain randomizes the sandbox path; fix this render-only input
				// so output hashes can be compared across benchmark processes.
				anchor := unboundAnchorPath
				unboundAnchorPath = "/var/lib/unbound/netos/root.key"
				b.Cleanup(func() { unboundAnchorPath = anchor })
				c := config.Default()
				c.DNS.Enabled = true
				c.DNS.Provider = "unbound"
				c.DNS.Upstreams = nil
				for i := 0; i < n; i++ {
					c.DNS.Upstreams = append(c.DNS.Upstreams, config.Upstream{ID: fmt.Sprintf("u%d", i), Type: "plain", Address: "192.0.2.53", Enabled: true})
				}
				index := 0
				if last {
					index = n - 1
				}
				for i := 0; i < n; i++ {
					c.DNS.SplitRules = append(c.DNS.SplitRules, config.DNSSplitRule{ID: fmt.Sprint(i), Enabled: true, Upstream: c.DNS.Upstreams[index].ID, Domains: []string{fmt.Sprintf("d%d.example", i)}})
				}
				u := NewUnbound(nil)
				b.Logf("SHA256 %x", sha256.Sum256([]byte(u.Render(c))))
				b.ReportAllocs()
				for b.Loop() {
					_ = u.Render(c)
				}
			})
		}
	}
}
