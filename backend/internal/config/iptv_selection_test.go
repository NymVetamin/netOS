package config

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestIPTVSelectionValidationTransitions(t *testing.T) {
	c := Default()
	c.Components = append(c.Components, Component{ID: "igmpproxy", Installed: true})
	c.Interfaces = []Interface{{ID: "lan", Name: "br0", Enabled: true}, {ID: "up", Name: "wan0", Enabled: true}}
	c.WANs = []WAN{{ID: "up", Interface: "up", Enabled: true, Proto: "dhcp"}}
	c.IPTV = IPTV{Enabled: true, Upstream: "up", Networks: []string{"lan"}}
	check := func(networkErrors, upstreamErrors int) {
		t.Helper()
		before, _ := json.Marshal(c)
		var r ValidationResult
		c.validateIPTV(&r)
		networks, upstream := 0, 0
		for _, p := range r.Problems {
			switch p.Path {
			case "iptv.networks":
				networks++
			case "iptv.upstream":
				upstream++
			default:
				t.Fatalf("unexpected problem %+v", p)
			}
		}
		if networks != networkErrors || upstream != upstreamErrors {
			t.Fatalf("network/upstream errors %d/%d want %d/%d: %+v", networks, upstream, networkErrors, upstreamErrors, r.Problems)
		}
		after, _ := json.Marshal(c)
		if !bytes.Equal(before, after) {
			t.Fatal("validation mutated config")
		}
	}
	check(1, 0)
	good := Network{ID: "lan", Interface: "lan", Enabled: true, RouterAddress: "192.0.2.1/24"}
	c.Networks = []Network{good}
	check(0, 0)
	c.Networks[0].Enabled = false
	check(1, 0)
	c.Networks[0] = good
	check(0, 0)
	for _, address := range []string{"bad", "2001:db8::1/64", ""} {
		c.Networks[0].RouterAddress = address
		check(1, 0)
	}
	c.Networks[0] = good
	check(0, 0)
	c.Networks[0].Interface = "up"
	check(1, 0)
	c.Networks[0].Interface = "missing"
	check(1, 0)
	c.Networks[0] = good
	c.Interfaces = append(c.Interfaces, Interface{ID: "lan", Name: "duplicate", Enabled: false})
	check(0, 0)
	c.Interfaces[0].Enabled = false
	c.Interfaces[2].Enabled = true
	check(1, 0)
	c.Interfaces[0].Enabled = true
	c.Interfaces = c.Interfaces[:2]
	check(0, 0)
	bad := good
	bad.RouterAddress = "bad"
	c.Networks = []Network{good, bad}
	check(1, 0)
	c.Networks = []Network{bad, good}
	check(0, 0)
	c.Networks[1].Enabled = false
	check(1, 0)
	c.Networks = []Network{good, bad}
	c.Networks[1].Enabled = false
	check(0, 0)
	c.IPTV.Networks = []string{"lan", "lan", "missing"}
	check(2, 0)
	c.IPTV.Networks = []string{"lan"}
	check(0, 0)
	c.Interfaces[1].Enabled = false
	check(0, 1)
	c.Interfaces[1].Enabled = true
	check(0, 0)
	c.IPTV.Networks = nil
	check(1, 0)
	c.IPTV.Enabled = false
	check(0, 0)
	c.IPTV.Enabled = true
	c.IPTV.Networks = []string{"lan"}
	check(0, 0)
}
