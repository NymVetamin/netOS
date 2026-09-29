package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestPolicySourceIntersection(t *testing.T) {
	cfg := config.Default()
	cfg.Networks = []config.Network{{ID: "lan", RouterAddress: "192.0.3.1/24"}}
	for _, tc := range []struct{ source, want string }{
		{"192.0.3.28/32", " -s 192.0.3.28/32"},
		{"192.0.0.0/16", " -s 192.0.3.0/24"},
		{"198.51.100.1/32", ""},
		{"", " -s 192.0.3.0/24"},
	} {
		got, possible := policySelectors(cfg, config.Policy{Network: "lan", SrcIP: tc.source})
		if got != tc.want || possible != (tc.want != "") || (possible && strings.Count(got, " -s ") != 1) {
			t.Errorf("source %q: %q, want %q", tc.source, got, tc.want)
		}
	}
}

func TestDisjointPolicySourcesEmitNoRule(t *testing.T) {
	cfg := config.Default()
	cfg.Networks = []config.Network{{ID: "lan", RouterAddress: "192.0.2.1/24"}}
	cfg.Policies = []config.Policy{{ID: "disjoint", Name: "must-not-match", Enabled: true, Network: "lan", SrcIP: "198.51.100.0/24", Channel: "direct"}}
	var b builder
	b.channelPolicies(cfg)
	if strings.Contains(b.String(), "must-not-match") {
		t.Fatalf("empty source intersection emitted a rule: %s", b.String())
	}
}

func TestVPNSourceIntersectionPreservesIPsecAndPeerScope(t *testing.T) {
	cfg := config.Default()
	cfg.VPNServers = []config.VPNServer{{ID: "ike", Type: "ikev2", Subnet: "10.2.0.1/24", Peers: []config.VPNPeer{{ID: "peer", Address: "10.2.0.2"}}}}
	for _, tc := range []struct {
		peer, source, want string
		possible           bool
	}{
		{"", "10.2.0.9/32", " -m policy --dir in --pol ipsec -s 10.2.0.9/32", true},
		{"peer", "10.0.0.0/8", " -m policy --dir in --pol ipsec -s 10.2.0.2/32", true},
		{"peer", "10.2.0.3/32", "", false},
	} {
		got, possible := policySelectors(cfg, config.Policy{VPNServer: "ike", VPNPeer: tc.peer, SrcIP: tc.source})
		if got != tc.want || possible != tc.possible {
			t.Fatalf("peer %q source %q: (%q, %v), want (%q, %v)", tc.peer, tc.source, got, possible, tc.want, tc.possible)
		}
	}
}
