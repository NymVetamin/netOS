package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestSambaAccessLimitsLANAndVPNBeforeGenericAccepts(t *testing.T) {
	c := config.Default()
	c.Interfaces = []config.Interface{{ID: "lanif", Name: "eth1", Enabled: true}}
	c.Networks = []config.Network{{ID: "lan", Enabled: true, Interface: "lanif", RouterAddress: "192.168.8.1/24", Zone: "lan"}}
	c.Samba = config.Samba{Enabled: true, Discovery: true, Networks: []string{"lan"}, VPNs: []string{"wg", "oc", "ipsec", "l2"}}
	c.VPNServers = []config.VPNServer{{ID: "wg", Index: 1, Enabled: true, Type: "wireguard", Subnet: "10.1.0.1/24"}, {ID: "oc", Index: 2, Enabled: true, Type: "ocserv", Subnet: "10.2.0.1/24"}, {ID: "ipsec", Index: 3, Enabled: true, Type: "ikev2", Subnet: "10.3.0.1/24"}, {ID: "l2", Index: 4, Enabled: true, Type: "l2tp", Subnet: "10.4.0.1/24"}, {ID: "other", Index: 5, Enabled: true, Type: "wireguard", Subnet: "10.5.0.1/24"}}
	b := &builder{}
	b.sambaAccess(c)
	rules := b.sb.String()
	for _, want := range []string{"-i eth1 -s 192.168.8.0/24 -p tcp --dport 445 -j ACCEPT", "-i wg-srv1 -s 10.1.0.0/24", "-i vpns2+ -s 10.2.0.0/24", "-m policy --dir in --pol ipsec -s 10.3.0.0/24", "--dports 445,3702 -j DROP", "-o eth1 -p igmp", "--dport 3702"} {
		if !strings.Contains(rules, want) {
			t.Fatalf("missing %s\n%s", want, rules)
		}
	}
	if strings.Contains(rules, "10.5.0.0") || strings.Contains(rules, "-i eth0") {
		t.Fatal("unselected VPN/WAN allowed")
	}
	if strings.Index(rules, "--dports 445,3702 -j DROP") < strings.Index(rules, "-i wg-srv1") {
		t.Fatal("drop precedes authorized VPN")
	}
	c.Samba.Enabled = false
	b = &builder{}
	b.sambaAccess(c)
	if b.sb.Len() != 0 {
		t.Fatal("disabled Samba left firewall rules")
	}
}
