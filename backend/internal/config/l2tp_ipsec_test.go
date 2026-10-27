package config

import "testing"

func TestL2TPIPsecValidationAndSharedPorts(t *testing.T) {
	c := Default()
	c.Components = append(c.Components, Component{ID: "l2tp", Installed: true}, Component{ID: "strongswan", Installed: true})
	l2 := VPNServer{ID: "l2tp", Index: 1, Name: "L2TP", Type: "l2tp", Enabled: true, Subnet: "10.99.0.1/24", Port: 1701, DefaultChannel: "direct", Config: map[string]any{"listen": "0.0.0.0", "ipsec": true, "preshared_key": "test-shared-ipsec-key", "dns": []string{"10.99.0.1", "1.1.1.1"}}, Peers: []VPNPeer{{ID: "alice", Name: "Alice", Enabled: true, Address: "10.99.0.2", Credentials: map[string]string{"username": "alice", "password": "long-secret"}}}}
	c.VPNServers = []VPNServer{l2}
	if r := c.Validate(); r.HasErrors() {
		t.Fatalf("protected server rejected: %+v", r.Problems)
	}
	c.VPNServers[0].Config["ipsec"] = false
	if r := c.Validate(); !hasErrorAt(r, "vpn_servers[0].config.listen") {
		t.Fatal("plain server may listen publicly")
	}
	c.VPNServers[0].Config["ipsec"] = true
	c.VPNServers[0].Config["preshared_key"] = "short"
	if r := c.Validate(); !hasErrorAt(r, "vpn_servers[0].config.preshared_key") {
		t.Fatal("short PSK accepted")
	}
	c.VPNServers[0].Config["preshared_key"] = "test-shared-ipsec-key"
	c.VPNServers = append(c.VPNServers, VPNServer{ID: "ike", Index: 2, Name: "IKE", Type: "ikev2", Enabled: true, Port: 500, Subnet: "10.98.0.1/24", DefaultChannel: "direct", Config: map[string]any{"server_identity": "vpn.example"}, Peers: []VPNPeer{{ID: "bob", Name: "Bob", Enabled: true, Address: "10.98.0.2", Credentials: map[string]string{"username": "bob", "password": "long-secret"}}}})
	if r := c.Validate(); r.HasErrors() {
		t.Fatalf("shared IPsec ports rejected: %+v", r.Problems)
	}
	c.Socks.Enabled = true
	c.Socks.Port = 500 // TCP is independent of IKE UDP.
	// A WireGuard UDP listener must still conflict with the shared IKE sockets.
	c.VPNServers = append(c.VPNServers, VPNServer{ID: "wg", Index: 3, Name: "WG", Type: "wireguard", Enabled: true, Port: 500, Subnet: "10.96.0.1/24"})
	if r := c.Validate(); !hasErrorAt(r, "vpn_servers[2].port") {
		t.Fatal("unrelated UDP500 conflict accepted")
	}
}
