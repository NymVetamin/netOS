package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestSegmentIsolationFollowsSelectedFirewallZone(t *testing.T) {
	for _, zone := range []string{"lan", "vpn", "wan", "guest"} {
		t.Run(zone, func(t *testing.T) {
			cfg := config.Default()
			cfg.WANs = nil
			cfg.Interfaces = []config.Interface{
				{ID: "source", Name: "eth1", Type: "physical", Enabled: true},
				{ID: "target", Name: "eth2", Type: "physical", Enabled: true},
			}
			cfg.Firewall.Zones = append(cfg.Firewall.Zones, config.Zone{Name: "guest", Policy: "accept"})
			cfg.Networks = []config.Network{
				{ID: "a", Name: "isolated", Interface: "source", Zone: zone, Enabled: true, Isolated: true, RouterAddress: "192.0.2.1/24"},
				{ID: "b", Name: "target", Interface: "target", Zone: "lan", Enabled: true, RouterAddress: "192.0.3.1/24"},
			}
			set, err := Build(cfg)
			if err != nil {
				t.Fatal(err)
			}
			prefix := "-A " + ChainName(zone, "FWD") + " -s 192.0.2.0/24 -d 192.0.3.0/24 "
			found := false
			for _, line := range strings.Split(set.IPv4, "\n") {
				if strings.HasPrefix(line, prefix) && strings.Contains(line, "-j REJECT") {
					found = true
				}
			}
			if !found {
				t.Fatalf("isolated segment in zone %s has no rejection in its forwarding path", zone)
			}
			cfg.Networks[0].Isolated = false
			set, err = Build(cfg)
			if err != nil || strings.Contains(set.IPv4, prefix) {
				t.Fatalf("disabling isolation retained the restriction: %v", err)
			}
		})
	}
}
