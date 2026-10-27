//go:build linux

package firewall

import (
	"context"
	"os"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationIPTVRulesSurviveSaveAndHealth(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("requires root and isolated network namespace")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	host, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if self == host {
		t.Fatal("refusing host network namespace")
	}
	c := config.Default()
	c.Interfaces = []config.Interface{{ID: "up", Name: "up0", Enabled: true}, {ID: "lan", Name: "br0", Enabled: true}}
	c.WANs = []config.WAN{{ID: "wan", Interface: "up", Proto: "dhcp", Enabled: true}}
	c.Networks = []config.Network{{ID: "lan", Interface: "lan", Zone: "lan", RouterAddress: "10.99.0.1/24", Enabled: true}}
	c.IPTV = config.IPTV{Enabled: true, Upstream: "wan", Networks: []string{"lan"}}
	s := New(system.NewExec(), t.TempDir())
	for _, policy := range []string{"accept", "drop"} {
		for _, sources := range [][]string{nil, {"192.0.2.0/24"}} {
			c.Firewall.OutputPolicy, c.IPTV.Sources = policy, sources
			if err := s.Apply(context.Background(), c); err != nil {
				t.Fatal(err)
			}
			if err := s.Health(context.Background(), c); err != nil {
				t.Fatalf("policy=%s sources=%v: %v", policy, sources, err)
			}
		}
	}
}
