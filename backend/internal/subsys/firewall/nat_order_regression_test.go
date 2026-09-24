package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestExplicitSNATPrecedesAutomaticMasquerade(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "wan", Name: "eth1"}}
	cfg.WANs = []config.WAN{{ID: "wan1", Name: "WAN1", Enabled: true, Interface: "wan"}}
	cfg.Firewall.NAT = []config.NATRule{{ID: "custom", Name: "custom", Enabled: true, Direction: "source", Interface: "eth1", Source: "192.0.2.0/24", ToSource: "198.18.0.3"}}
	var b builder
	b.nat(cfg, buildZoneMap(cfg))
	out := b.String()
	custom := strings.Index(out, "-A POSTROUTING -o eth1 -s 192.0.2.0/24")
	general := strings.Index(out, "-A POSTROUTING -o eth1 -m comment")
	if custom < 0 || general < 0 || custom >= general {
		t.Fatalf("explicit SNAT must precede general masquerade:\n%s", out)
	}
}
