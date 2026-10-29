package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestInternetBlockPreservesInternalAndRouterAccess(t *testing.T) {
	cfg := config.Default()
	cfg.Clients = []config.Client{{ID: "phone", MAC: "02:00:00:00:00:02", Channel: config.InternetBlockChannel}}
	cfg.Networks = append(cfg.Networks, config.Network{ID: "other", Enabled: true, RouterAddress: "10.22.0.1/24"})
	for _, enabled := range []bool{true, false} {
		cfg.Firewall.Enabled = enabled
		rs, err := Build(cfg)
		if err != nil {
			t.Fatal(err)
		}
		rules := rs.IPv4
		for _, want := range []string{"-A FORWARD -m mac --mac-source 02:00:00:00:00:02", "-A NETOS-INTERNET-BLOCK -d 10.22.0.0/24 -j RETURN", "-A NETOS-INTERNET-BLOCK -j DROP", "-A NETOS-POLICY -m mac --mac-source 02:00:00:00:00:02 -j RETURN"} {
			if !strings.Contains(rules, want) {
				t.Fatalf("missing %s", want)
			}
		}
		if strings.Contains(rules, "-A INPUT -m mac --mac-source") {
			t.Fatal("internet block denied router services")
		}
		if enabled && strings.Index(rules, "-A FORWARD -m mac") > strings.Index(rules, "--ctstate ESTABLISHED,RELATED") {
			t.Fatal("block after established")
		}
	}
	cfg.Clients[0].Channel = "direct"
	rs, _ := Build(cfg)
	if strings.Contains(rs.IPv4, "NETOS-INTERNET-BLOCK") {
		t.Fatal("unblock left rules")
	}
}

func TestInternetBlockVPNAndIPv6Selectors(t *testing.T) {
	cfg := config.Default()
	cfg.IPv6.Mode = "passthrough"
	cfg.Clients = []config.Client{{MAC: "02:00:00:00:00:02", Channel: config.InternetBlockChannel}}
	for i, kind := range []string{"wireguard", "ocserv", "ikev2", "l2tp", "xray"} {
		cfg.VPNServers = append(cfg.VPNServers, config.VPNServer{ID: kind, Index: i + 1, Type: kind, Enabled: true, Subnet: "10.9.0.1/24", Peers: []config.VPNPeer{{ID: "p", Enabled: true, Address: "10.9.0.2", Channel: config.InternetBlockChannel}}})
	}
	matches := internetBlockMatches(cfg, false)
	if len(matches) != 5 {
		t.Fatalf("matches: %v", matches)
	}
	if !strings.Contains(strings.Join(matches, "\n"), "--pol ipsec") {
		t.Fatal("IKE peer loses IPsec selector")
	}
	rs, _ := Build(cfg)
	if !strings.Contains(rs.IPv6, "-A FORWARD -m mac --mac-source 02:00:00:00:00:02") {
		t.Fatal("IPv6 bypass")
	}
}
