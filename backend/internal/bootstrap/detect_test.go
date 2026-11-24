package bootstrap

import "testing"

func TestSubnetOf(t *testing.T) {
	for input, want := range map[string]string{
		"192.0.2.129/24": "192.0.2.0/24",
		"0.0.0.0/0":      "0.0.0.0/0",
		"192.0.2.1/99":   "192.0.2.1/99",
		"999.0.0.1/24":   "999.0.0.1/24",
		"2001:db8::1/64": "2001:db8::1/64",
	} {
		if got := subnetOf(input); got != want {
			t.Errorf("subnetOf(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestInitialWANUsesOnlyEffectiveDHCPv4DNS(t *testing.T) {
	data := `{"DNS":[{"Family":2,"Address":[192,0,2,53],"ConfigSource":"DHCPv4"},{"Family":2,"Address":[192,0,2,54],"ConfigSource":"static"},{"Family":2,"Address":[127,0,0,53],"ConfigSource":"DHCPv4"},{"Family":2,"Address":[192,0,2,55],"ConfigSource":"DHCPv4"}]}`
	d := &Detected{WANInterface: "eth0", WANAddress: "192.0.2.1/24", WANGateway: "192.0.2.254", WANDNS: dhcpLinkDNS(data)}
	c, err := BuildInitial(d)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.WANs[0].DNSServers; len(got) != 2 || got[0] != "192.0.2.53" || got[1] != "192.0.2.55" {
		t.Fatalf("static WAN DNS: %v", got)
	}
	d.WANGateway = ""
	c, err = BuildInitial(d)
	if err != nil || len(c.WANs[0].DNSServers) != 0 {
		t.Fatalf("DHCP configuration: %v, %v", c, err)
	}
	for _, bad := range []string{"", "{}", "bad JSON", `{"DNS":[{"Family":2,"Address":[1,2],"ConfigSource":"DHCPv4"}]}`} {
		if len(dhcpLinkDNS(bad)) != 0 {
			t.Errorf("unexpected DNS from %q", bad)
		}
	}
}
