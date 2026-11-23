package config

import (
	"fmt"
	"testing"
)

func networkIdentityConfig(n int) *Config {
	c := Default()
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("lan%d", i)
		c.Interfaces = append(c.Interfaces, Interface{ID: id, Name: id, Type: "physical", Enabled: true})
		c.Networks = append(c.Networks, Network{
			ID: id, Name: id, Interface: id, Zone: "lan", Enabled: true,
			RouterAddress: fmt.Sprintf("10.%d.%d.1/24", i/256, i%256),
		})
	}
	c.Normalize()
	return c
}

func TestNetworkIDsUniqueAcrossEnabledAndDisabledSegments(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			c := networkIdentityConfig(2)
			c.Networks[1].Enabled = enabled
			if v := c.Validate(); v.HasErrors() {
				t.Fatal(v.Problems)
			}
			c.Networks[1].ID = c.Networks[0].ID
			for range 2 {
				c.Normalize()
				v := c.Validate()
				found := false
				for _, p := range v.Problems {
					if p.Path == "networks[1].id" && p.Severity == "error" {
						found = true
					}
				}
				if !found {
					t.Fatalf("duplicate ID accepted: %v", v.Problems)
				}
				if c.Networks[0].ID != c.Networks[1].ID {
					t.Fatal("validation changed segment identities")
				}
			}
			c.Networks[1].ID = "other"
			if v := c.Validate(); v.HasErrors() {
				t.Fatalf("fixed ID still rejected: %v", v.Problems)
			}
		})
	}
}

func BenchmarkValidateNetworkIdentities(b *testing.B) {
	for _, n := range []int{16, 256} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			c := networkIdentityConfig(n)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if v := c.Validate(); v.HasErrors() {
					b.Fatal(v.Problems)
				}
			}
		})
	}
}
