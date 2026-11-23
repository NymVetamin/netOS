package firewall

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func macFilterConfig(n int, mac string) *config.Config {
	c := config.Default()
	for i := 0; i < n; i++ {
		c.Firewall.Rules = append(c.Firewall.Rules, config.FirewallRule{ID: fmt.Sprintf("mac-%d", i), Enabled: true, Zone: "global", Flow: "in", Action: "drop", SrcMAC: mac})
		c.Policies = append(c.Policies, config.Policy{ID: fmt.Sprintf("p-%d", i), Enabled: true, Channel: config.InternetBlockChannel, SrcMAC: mac})
	}
	return c
}

func TestMACFilterSpellings(t *testing.T) {
	canonical, err := Build(macFilterConfig(2, "02:ab:cd:ef:00:01"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(canonical.IPv4, "--mac-source 02:ab:cd:ef:00:01") < 4 {
		t.Fatal("missing filter or policy selector")
	}
	for _, mac := range []string{"02-ab-cd-ef-00-01", "02-AB-CD-EF-00-01", "02ab.cdef.0001", "02AB.CDEF.0001"} {
		t.Run(mac, func(t *testing.T) {
			c := macFilterConfig(2, mac)
			if v := c.Validate(); v.HasErrors() {
				t.Fatalf("validation: %+v", v)
			}
			before, _ := json.Marshal(c)
			for range 2 {
				got, err := Build(c)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, canonical) {
					t.Fatal("ruleset differs from same canonical MAC")
				}
			}
			after, _ := json.Marshal(c)
			if string(before) != string(after) {
				t.Fatal("configuration mutated")
			}
		})
	}
}

func BenchmarkBuildMACFilters(b *testing.B) {
	for _, n := range []int{8, 512} {
		for _, mac := range []string{"02:ab:cd:ef:00:01", "02-AB-CD-EF-00-01"} {
			b.Run(fmt.Sprintf("%d/%s", n, mac), func(b *testing.B) {
				c := macFilterConfig(n, mac)
				b.ReportAllocs()
				for b.Loop() {
					if _, err := Build(c); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func TestFilterMACPreservesOtherInput(t *testing.T) {
	for _, value := range []string{"", "02:AB:CD:EF:00:01", "invalid", "02-00-00-00-00-00-00-01", "bad.mac", "02:00:00:00:00:00:00:01"} {
		if got := filterMAC(value); got != value {
			t.Fatalf("%q changed to %q", value, got)
		}
	}
}
