package firewall

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/netos-router/netos/internal/config"
	"reflect"
	"testing"
)

func zoneRuleFixture(n int) *config.Config {
	c := config.Default()
	c.Firewall.Zones = nil
	c.Firewall.Rules = nil
	c.Networks = nil
	c.Interfaces = nil
	for i := 0; i < n; i++ {
		zone := fmt.Sprintf("zone%d", i)
		iface := fmt.Sprintf("eth%d", i)
		c.Interfaces = append(c.Interfaces, config.Interface{ID: iface, Name: iface})
		c.Networks = append(c.Networks, config.Network{ID: zone, Interface: iface, Zone: zone, RouterAddress: fmt.Sprintf("10.%d.0.1/24", i), Enabled: true})
		c.Firewall.Zones = append(c.Firewall.Zones, config.Zone{Name: zone, Policy: "drop"})
		for j := 0; j < 8; j++ {
			c.Firewall.Rules = append(c.Firewall.Rules, config.FirewallRule{ID: fmt.Sprintf("r%d-%d", i, j), Name: fmt.Sprintf("rule%d-%d", i, j), Zone: zone, Flow: []string{"in", "out", "forward", "any"}[j%4], Enabled: j%3 != 0, Action: "accept", Protocol: "tcp", DstPort: "443"})
		}
	}
	return c
}

func TestZoneRuleIndexMatchesScan(t *testing.T) {
	for variant := 0; variant < 10; variant++ {
		c := zoneRuleFixture(3)
		c.Firewall.Rules = append(c.Firewall.Rules, config.FirewallRule{ID: "global", Name: "global", Zone: "global", Flow: "any", Enabled: true, Action: "drop"})
		switch variant {
		case 1:
			c.Firewall.Enabled = false
		case 2:
			c.Firewall.Zones = append(c.Firewall.Zones, c.Firewall.Zones[0])
		case 3:
			c.Firewall.Rules[2].DstZone = "zone1"
			c.Firewall.Rules[6].DstZone = "missing"
		case 4:
			c.Firewall.Rules[2].DstZone = "zone1"
			c.Firewall.Rules[2].OutInterface = "eth2"
		case 5:
			c.Networks = nil
		case 6:
			c.Firewall.Rules = append(c.Firewall.Rules, c.Firewall.Rules...)
		case 7:
			c.Firewall.Rules[1].Zone = "unknown"
			c.Firewall.Rules[2].Flow = "unknown"
		case 8:
			c.Firewall.Zones[0].Name = "global"
			c.Networks[0].Zone = "global"
			c.Firewall.Rules[1].Zone = "global"
		case 9:
			for i := range c.Firewall.Rules {
				c.Firewall.Rules[i].Enabled = false
			}
		}
		for repeat := 0; repeat < 2; repeat++ {
			before, _ := json.Marshal(c)
			zones := buildZoneMap(c)
			var b builder
			b.mangle(c, zones)
			b.nat(c, zones)
			b.filterScanReference(c, zones)
			want := &Ruleset{IPv4: b.String(), IPv6: buildIPv6(c), RuleIDs: b.ruleIDs}
			got, err := Build(c)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("variant%d repeat%d differs: %v", variant, repeat, err)
			}
			after, _ := json.Marshal(c)
			if string(before) != string(after) {
				t.Fatal("config mutated")
			}
			c.Firewall.Rules[1].Enabled = !c.Firewall.Rules[1].Enabled
		}
	}
}

func BenchmarkBuildZoneRules(b *testing.B) {
	for _, n := range []int{8, 256} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			c := zoneRuleFixture(n)
			rs, _ := Build(c)
			data, _ := json.Marshal(rs)
			b.Logf("output SHA256 %x", sha256.Sum256(data))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Build(c); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
