package monitor

import (
	"fmt"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func scopeFixture(n int) *config.Config {
	c := &config.Config{}
	c.TrafficMonitor.Enabled = true
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("lan%d", i)
		c.Interfaces = append(c.Interfaces, config.Interface{ID: id, Name: id, Enabled: true})
		c.Networks = append(c.Networks, config.Network{Interface: id, Enabled: true, RouterAddress: fmt.Sprintf("10.%d.%d.1/24", i/256, i%256)})
	}
	return c
}

func TestClientScopeConfiguredNetworksAndFreshness(t *testing.T) {
	c := scopeFixture(1)
	c.Networks[0].RouterAddress = "203.0.113.1/24"
	c.VPNServers = []config.VPNServer{{Type: "wireguard", Index: 1, Enabled: true, Subnet: "198.51.100.1/24"}, {Type: "xray", Index: 2, Enabled: true, Subnet: "10.2.0.1/24"}}
	s := NewClientScope(c)
	for _, a := range []string{"203.0.113.2", "198.51.100.2"} {
		if !s.Contains(a) {
			t.Fatal("configured client rejected", a)
		}
	}
	for _, a := range []string{"8.8.8.8", "10.2.0.2", "10.9.0.2", "bad", ""} {
		if s.Contains(a) {
			t.Fatal("unconfigured client accepted", a)
		}
	}
	c.Networks[0].Enabled = false
	c.VPNServers[0].Subnet = "192.0.2.1/24"
	fresh := NewClientScope(c)
	if fresh.Contains("203.0.113.2") || fresh.Contains("198.51.100.2") || !fresh.Contains("192.0.2.2") {
		t.Fatal("stale scope")
	}
	if !s.Contains("203.0.113.2") {
		t.Fatal("operation snapshot mutated")
	}
}

func TestClientScopeRuleCountAndDeterminism(t *testing.T) {
	c := scopeFixture(256)
	a := Render(c, false)
	if strings.Count(a, "add rule ") != 2 {
		t.Fatal("rules grow per network")
	}
	for i := 0; i < 5; i++ {
		if Render(c, false) != a {
			t.Fatal("nondeterministic render")
		}
	}
	c.Interfaces[0].Enabled = false
	if NewClientScope(c).Contains("10.0.0.2") {
		t.Fatal("disabled interface remains in scope")
	}
}

func BenchmarkClientScopeOperation(b *testing.B) {
	for _, n := range []int{4, 256} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			c := scopeFixture(n)
			addresses := make([]string, n*16)
			for i := range addresses {
				addresses[i] = fmt.Sprintf("10.%d.%d.%d", (i/16)/256, (i/16)%256, 2+i%16)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s := NewClientScope(c)
				for _, a := range addresses {
					if !s.Contains(a) {
						b.Fatal(a)
					}
				}
			}
		})
	}
}

func BenchmarkAccountingRender(b *testing.B) {
	for _, n := range []int{4, 256} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			c := scopeFixture(n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Render(c, true)
			}
		})
	}
}
