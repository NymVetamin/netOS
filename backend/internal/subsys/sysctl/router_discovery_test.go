package sysctl

import (
	"reflect"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestRouterDiscoveryUsesOnlyUnconfiguredWANLinks(t *testing.T) {
	cfg := &config.Config{
		Interfaces: []config.Interface{
			{ID: "a", Name: "eth0", Enabled: true}, {ID: "b", Name: "eth1", Enabled: true},
			{ID: "c", Name: "eth2", Enabled: true}, {ID: "d", Name: "eth3", Enabled: true},
		},
		WANs: []config.WAN{
			{Interface: "a", Enabled: true}, {Interface: "a", Enabled: true},
			{Interface: "b", Enabled: true}, {ID: "isp", Interface: "c", Proto: "pppoe", Enabled: true},
			{Interface: "d", Enabled: false},
		},
	}
	state := "fe80 0a 40 20 80 eth0\n2001 0b 40 00 00 eth1\nfe80 0b 40 20 80 eth1\n" +
		"fe80 0c 40 20 80 eth2\nfe80 0d 40 20 80 ppp-isp\nfe80 0e 40 20 80 eth3\nfe80 10 40 20 80 lan\n"
	if got := routerDiscoveryTargets(cfg, state); !reflect.DeepEqual(got, []int{10, 13}) {
		t.Fatalf("initial solicitation targets: %v", got)
	}
	state += "2001 0a 40 00 00 eth0\n2001 0d 40 00 00 ppp-isp\n"
	if got := routerDiscoveryTargets(cfg, state); len(got) != 0 {
		t.Fatalf("solicitation repeated after address assignment: %v", got)
	}
}
