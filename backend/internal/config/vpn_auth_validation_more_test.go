package config

import "testing"

func validIKEv2Config() *Config {
	cfg := Default()
	cfg.Components = []Component{{ID: "strongswan", Installed: true}}
	cfg.VPNServers = []VPNServer{{
		ID: "ike", Index: 1, Name: "IKEv2", Enabled: true, Type: "ikev2",
		Subnet: "10.20.0.1/24", Port: 500,
		Config: map[string]any{
			"public_endpoint": "vpn.example.com", "server_identity": "vpn.example.com",
			"dns": []string{"1.1.1.1"}, "split_routes": []string{"192.168.0.0/16"}, "mtu": 1400,
		},
		Peers: []VPNPeer{{
			ID: "alice", Name: "Alice", Enabled: true, Address: "10.20.0.2",
			Credentials: map[string]string{"username": "alice", "password": "long-password"},
		}},
	}}
	return cfg
}

func validOcservConfig() *Config {
	cfg := Default()
	cfg.Components = []Component{{ID: "ocserv", Installed: true}}
	cfg.VPNServers = []VPNServer{{
		ID: "oc", Index: 1, Name: "OpenConnect", Enabled: true, Type: "ocserv",
		Subnet: "10.21.0.1/24", Port: 443,
		Config: map[string]any{
			"public_endpoint": "vpn.example.com:443", "dns": []string{"9.9.9.9"},
			"routes": []string{"10.0.0.0/8"}, "mtu": 1380, "banner": "Authorized users only",
		},
		Peers: []VPNPeer{{
			ID: "bob", Name: "Bob", Enabled: true, Address: "10.21.0.2",
			Credentials: map[string]string{"username": "bob", "password": "long-password"},
		}},
	}}
	return cfg
}

func TestIKEv2EveryFieldValid(t *testing.T) {
	if result := validIKEv2Config().Validate(); result.HasErrors() {
		t.Fatalf("valid IKEv2 rejected: %+v", result.Problems)
	}
	for _, endpoint := range []string{"192.0.2.1", "vpn.example.com"} {
		cfg := validIKEv2Config()
		cfg.VPNServers[0].Config["public_endpoint"] = endpoint
		cfg.VPNServers[0].Config["server_identity"] = endpoint
		if result := cfg.Validate(); result.HasErrors() {
			t.Fatalf("valid endpoint %q rejected: %+v", endpoint, result.Problems)
		}
	}
}

func TestIKEv2RejectsSecondEnabledPeer(t *testing.T) {
	cfg := validIKEv2Config()
	second := cfg.VPNServers[0].Peers[0]
	second.ID = "bob"
	second.Name = "Bob"
	second.Address = "10.20.0.3"
	second.Credentials = map[string]string{"username": "bob", "password": "long-password"}
	cfg.VPNServers[0].Peers = append(cfg.VPNServers[0].Peers, second)
	if !hasErrorAt(cfg.Validate(), "vpn_servers[0].peers[1].enabled") {
		t.Fatalf("second enabled IKEv2 peer was accepted: %+v", cfg.Validate().Problems)
	}
	cfg.VPNServers[0].Peers[1].Enabled = false
	if result := cfg.Validate(); result.HasErrors() {
		t.Fatalf("disabled IKEv2 draft peer was rejected: %+v", result.Problems)
	}
}

func TestIKEv2EveryInvalidField(t *testing.T) {
	tests := []struct {
		name string
		path string
		edit func(*Config)
	}{
		{"port", "vpn_servers[0].port", func(c *Config) { c.VPNServers[0].Port = 501 }},
		{"endpoint", "vpn_servers[0].config.public_endpoint", func(c *Config) { c.VPNServers[0].Config["public_endpoint"] = "vpn.example.com:500" }},
		{"identity", "vpn_servers[0].config.server_identity", func(c *Config) { c.VPNServers[0].Config["server_identity"] = "bad identity" }},
		{"missing identity", "vpn_servers[0].config.server_identity", func(c *Config) {
			c.VPNServers[0].Config["server_identity"] = ""
			c.VPNServers[0].Config["public_endpoint"] = ""
		}},
		{"MTU low", "vpn_servers[0].config.mtu", func(c *Config) { c.VPNServers[0].Config["mtu"] = 1279 }},
		{"MTU high", "vpn_servers[0].config.mtu", func(c *Config) { c.VPNServers[0].Config["mtu"] = 9001 }},
		{"DNS", "vpn_servers[0].config.dns[0]", func(c *Config) { c.VPNServers[0].Config["dns"] = []string{"2001:db8::1"} }},
		{"route", "vpn_servers[0].config.split_routes[0]", func(c *Config) { c.VPNServers[0].Config["split_routes"] = []string{"2001:db8::/32"} }},
		{"username empty", "vpn_servers[0].peers[0].credentials.username", func(c *Config) { c.VPNServers[0].Peers[0].Credentials["username"] = "" }},
		{"username unsafe", "vpn_servers[0].peers[0].credentials.username", func(c *Config) { c.VPNServers[0].Peers[0].Credentials["username"] = "bad user" }},
		{"username duplicate", "vpn_servers[0].peers[1].credentials.username", func(c *Config) {
			peer := c.VPNServers[0].Peers[0]
			peer.ID, peer.Address = "second", "10.20.0.3"
			c.VPNServers[0].Peers = append(c.VPNServers[0].Peers, peer)
		}},
		{"password short", "vpn_servers[0].peers[0].credentials.password", func(c *Config) { c.VPNServers[0].Peers[0].Credentials["password"] = "short" }},
		{"password control", "vpn_servers[0].peers[0].credentials.password", func(c *Config) { c.VPNServers[0].Peers[0].Credentials["password"] = "long\npassword" }},
		{"unknown config", "vpn_servers[0].config", func(c *Config) { c.VPNServers[0].Config["unknown"] = true }},
		{"unencodable config", "vpn_servers[0].config", func(c *Config) { c.VPNServers[0].Config["mtu"] = func() {} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validIKEv2Config()
			test.edit(cfg)
			if !hasErrorAt(cfg.Validate(), test.path) {
				t.Fatalf("invalid IKEv2 accepted; expected %s: %+v", test.path, cfg.Validate().Problems)
			}
		})
	}
}

func TestOcservEveryFieldValid(t *testing.T) {
	if result := validOcservConfig().Validate(); result.HasErrors() {
		t.Fatalf("valid ocserv rejected: %+v", result.Problems)
	}
	for _, mtu := range []int{0, 576, 9000} {
		cfg := validOcservConfig()
		cfg.VPNServers[0].Config["mtu"] = mtu
		if result := cfg.Validate(); result.HasErrors() {
			t.Fatalf("valid MTU %d rejected: %+v", mtu, result.Problems)
		}
	}
}

func TestOcservEveryInvalidField(t *testing.T) {
	tests := []struct {
		name string
		path string
		edit func(*Config)
	}{
		{"port low", "vpn_servers[0].port", func(c *Config) { c.VPNServers[0].Port = 0 }},
		{"port high", "vpn_servers[0].port", func(c *Config) { c.VPNServers[0].Port = 65536 }},
		{"endpoint no port", "vpn_servers[0].config.public_endpoint", func(c *Config) { c.VPNServers[0].Config["public_endpoint"] = "vpn.example.com" }},
		{"endpoint bad host", "vpn_servers[0].config.public_endpoint", func(c *Config) { c.VPNServers[0].Config["public_endpoint"] = "bad host:443" }},
		{"endpoint bad port", "vpn_servers[0].config.public_endpoint", func(c *Config) { c.VPNServers[0].Config["public_endpoint"] = "vpn.example.com:65536" }},
		{"MTU low", "vpn_servers[0].config.mtu", func(c *Config) { c.VPNServers[0].Config["mtu"] = 575 }},
		{"MTU high", "vpn_servers[0].config.mtu", func(c *Config) { c.VPNServers[0].Config["mtu"] = 9001 }},
		{"banner", "vpn_servers[0].config.banner", func(c *Config) { c.VPNServers[0].Config["banner"] = "hello\nnext" }},
		{"DNS", "vpn_servers[0].config.dns[0]", func(c *Config) { c.VPNServers[0].Config["dns"] = []string{"dns.example"} }},
		{"route", "vpn_servers[0].config.routes[0]", func(c *Config) { c.VPNServers[0].Config["routes"] = []string{"invalid"} }},
		{"username", "vpn_servers[0].peers[0].credentials.username", func(c *Config) { c.VPNServers[0].Peers[0].Credentials["username"] = ".." }},
		{"username duplicate", "vpn_servers[0].peers[1].credentials.username", func(c *Config) {
			peer := c.VPNServers[0].Peers[0]
			peer.ID, peer.Address = "second", "10.21.0.3"
			c.VPNServers[0].Peers = append(c.VPNServers[0].Peers, peer)
		}},
		{"password short", "vpn_servers[0].peers[0].credentials.password", func(c *Config) { c.VPNServers[0].Peers[0].Credentials["password"] = "short" }},
		{"password control", "vpn_servers[0].peers[0].credentials.password", func(c *Config) { c.VPNServers[0].Peers[0].Credentials["password"] = "long\x00password" }},
		{"unknown config", "vpn_servers[0].config", func(c *Config) { c.VPNServers[0].Config["unknown"] = true }},
		{"unencodable config", "vpn_servers[0].config", func(c *Config) { c.VPNServers[0].Config["mtu"] = func() {} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validOcservConfig()
			test.edit(cfg)
			if !hasErrorAt(cfg.Validate(), test.path) {
				t.Fatalf("invalid ocserv accepted; expected %s: %+v", test.path, cfg.Validate().Problems)
			}
		})
	}
}
