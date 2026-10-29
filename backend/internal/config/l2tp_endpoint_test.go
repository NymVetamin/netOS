package config

import "testing"

func TestL2TPConnectionAddress(t *testing.T) {
	for _, tc := range []struct {
		address string
		valid   bool
	}{{"", true}, {"vpn.example.com", true}, {"198.51.100.20", true}, {"192.168.1.1", true}, {"https://vpn.example.com", false}, {"vpn.example.com:1701", false}, {"0.0.0.0", false}, {"::1", false}, {"224.0.0.1", false}, {"bad name", false}} {
		t.Run(tc.address, func(t *testing.T) {
			c := Default()
			c.Components = append(c.Components, Component{ID: "l2tp", Installed: true}, Component{ID: "strongswan", Installed: true})
			c.VPNServers = []VPNServer{{ID: "test", Name: "test", Index: 1, Type: "l2tp", Enabled: true, Port: 1701, Subnet: "10.99.0.1/24", DefaultChannel: "direct", Config: map[string]any{"listen": "0.0.0.0", "ipsec": true, "preshared_key": "test-shared-ipsec-key", "public_endpoint": tc.address}}}
			r := c.Validate()
			if hasErrorAt(r, "vpn_servers[0].config.public_endpoint") == tc.valid {
				t.Fatalf("unexpected validation %+v", r.Problems)
			}
			parsed, err := c.VPNServers[0].L2TPConfig()
			if err != nil || parsed.PublicEndpoint != tc.address || parsed.Listen != "0.0.0.0" {
				t.Fatalf("lost endpoint/listener: %+v %v", parsed, err)
			}
		})
	}
}
