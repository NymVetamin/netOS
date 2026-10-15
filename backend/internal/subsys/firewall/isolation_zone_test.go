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
			prefix := "-A " + ChainName(zone, "ISOLATION") + " -s 192.0.2.0/24 -d 192.0.3.0/24 "
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
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(set.IPv4, "\n") {
				if strings.HasPrefix(line, prefix) && strings.Contains(line, "изоляция") {
					t.Fatalf("disabling isolation retained its dedicated restriction: %s", line)
				}
			}
		})
	}
}

func TestIsolationRejectsBothDirections(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{
		{ID: "a", Name: "eth1", Type: "physical", Enabled: true},
		{ID: "b", Name: "eth2", Type: "physical", Enabled: true},
	}
	cfg.Networks = []config.Network{
		{ID: "a", Interface: "a", Zone: "lan", Enabled: true, RouterAddress: "192.0.2.1/24"},
		{ID: "b", Interface: "b", Zone: "lan", Enabled: true, Isolated: true, RouterAddress: "192.0.3.1/24"},
	}
	set, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, direction := range []string{
		"-s 192.0.2.0/24 -d 192.0.3.0/24",
		"-s 192.0.3.0/24 -d 192.0.2.0/24",
	} {
		if !strings.Contains(set.IPv4, "-A LAN-ISOLATION "+direction) {
			t.Fatalf("missing rejection for %s", direction)
		}
	}
}

func TestIsolationLANAndVPNOnlyInSourceZone(t *testing.T) {
	cfg := config.Default()
	cfg.Networks = []config.Network{
		{ID: "lan", Name: "LAN", Enabled: true, Zone: "lan", Interface: "lan", RouterAddress: "192.168.1.1/24", Isolated: true},
		{ID: "other", Name: "Other", Enabled: true, Zone: "lan", Interface: "other", RouterAddress: "192.168.2.1/24"},
	}
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "eth1", Enabled: true}, {ID: "other", Name: "eth2", Enabled: true}}
	cfg.VPNServers = []config.VPNServer{{ID: "wg", Name: "WG", Enabled: true, Type: "wireguard", Index: 1, Subnet: "10.9.0.1/24"}, {ID: "oc", Name: "OC", Enabled: true, Type: "ocserv", Index: 2, Subnet: "10.10.0.1/24"}}
	for _, vpnIsolation := range []bool{false, true} {
		cfg.VPNServers[0].Isolated = vpnIsolation
		r, _ := Build(cfg)
		for _, want := range []string{
			"-A LAN-ISOLATION -s 192.168.1.0/24 -d 10.9.0.0/24",
			"-A VPN-ISOLATION -s 10.9.0.0/24 -d 192.168.1.0/24",
		} {
			if !strings.Contains(r.IPv4, want) {
				t.Fatal("missing", want)
			}
		}
		if strings.Contains(r.IPv4, "WAN-ISOLATION") || strings.Contains(r.IPv4, "intersegment default") {
			t.Fatal("unrelated or duplicate rules", r.IPv4)
		}
		if strings.Contains(r.IPv4, "-A VPN-ISOLATION -s 192.168.") {
			t.Fatal("LAN source in VPN chain")
		}
		vpnPair := "-A VPN-ISOLATION -s 10.9.0.0/24 -d 10.10.0.0/24"
		if strings.Contains(r.IPv4, vpnPair) != vpnIsolation {
			t.Fatal("VPN toggle not enforced")
		}
		if strings.Index(r.IPv4, "-A FORWARD -s 192.168.1.0/24") > strings.Index(r.IPv4, "--ctstate ESTABLISHED,RELATED") && strings.Contains(r.IPv4, "--ctstate ESTABLISHED,RELATED") {
			t.Fatal("isolation after established")
		}
	}
	cfg.Networks[0].Isolated = false
	cfg.VPNServers[0].Isolated = false
	r, _ := Build(cfg)
	if strings.Contains(r.IPv4, "ISOLATION") {
		t.Fatal("isolation retained while off")
	}
	if strings.Contains(r.IPv4, "-A VPN-FWD -s 192.168.") || strings.Contains(r.IPv4, "-A WAN-FWD -s 192.168.") {
		t.Fatal("default in wrong zone")
	}
}
