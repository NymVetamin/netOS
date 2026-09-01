package config

import "testing"

func validOpenConnectConfig() *Config {
	cfg := Default()
	cfg.Components = []Component{{ID: "openconnect", Installed: true}}
	cfg.Channels = append(cfg.Channels, Channel{
		ID: "office", Index: 2, Name: "Office", Enabled: true,
		Type: "openconnect", Mode: "tun", FailMode: "block",
		Config: map[string]any{
			"server": "https://vpn.example.com", "username": "alice", "password": "long-password",
			"protocol": "anyconnect", "authgroup": "staff", "servercert": "sha256:abcdef",
			"mtu": 1400, "no_dtls": true, "no_system_trust": true,
		},
	})
	return cfg
}

func TestOpenConnectEveryFieldAndProtocolValid(t *testing.T) {
	for _, protocol := range []string{"", "anyconnect", "nc", "pulse", "gp", "f5", "fortinet", "array"} {
		cfg := validOpenConnectConfig()
		cfg.Channels[1].Config["protocol"] = protocol
		if result := cfg.Validate(); result.HasErrors() {
			t.Fatalf("valid OpenConnect protocol %q rejected: %+v", protocol, result.Problems)
		}
	}
	for _, mtu := range []int{0, 576, 9000} {
		cfg := validOpenConnectConfig()
		cfg.Channels[1].Config["mtu"] = mtu
		if result := cfg.Validate(); result.HasErrors() {
			t.Fatalf("valid OpenConnect MTU %d rejected: %+v", mtu, result.Problems)
		}
	}
}

func TestOpenConnectEveryInvalidField(t *testing.T) {
	tests := []struct {
		name string
		path string
		edit func(*Config)
	}{
		{"mode", "channels[1].mode", func(c *Config) { c.Channels[1].Mode = "socks" }},
		{"empty server", "channels[1].config.server", func(c *Config) { c.Channels[1].Config["server"] = "" }},
		{"HTTP server", "channels[1].config.server", func(c *Config) { c.Channels[1].Config["server"] = "http://vpn.example.com" }},
		{"server without host", "channels[1].config.server", func(c *Config) { c.Channels[1].Config["server"] = "https:///vpn" }},
		{"empty username", "channels[1].config.username", func(c *Config) { c.Channels[1].Config["username"] = "" }},
		{"empty password", "channels[1].config.password", func(c *Config) { c.Channels[1].Config["password"] = "" }},
		{"username newline", "channels[1].config.username", func(c *Config) { c.Channels[1].Config["username"] = "alice\nroot" }},
		{"password newline", "channels[1].config.password", func(c *Config) { c.Channels[1].Config["password"] = "long\npassword" }},
		{"authgroup newline", "channels[1].config.authgroup", func(c *Config) { c.Channels[1].Config["authgroup"] = "staff\nadmin" }},
		{"certificate newline", "channels[1].config.servercert", func(c *Config) { c.Channels[1].Config["servercert"] = "sha256:a\nb" }},
		{"missing pinned certificate", "channels[1].config.servercert", func(c *Config) {
			c.Channels[1].Config["no_system_trust"] = true
			c.Channels[1].Config["servercert"] = ""
		}},
		{"protocol", "channels[1].config.protocol", func(c *Config) { c.Channels[1].Config["protocol"] = "unknown" }},
		{"MTU low", "channels[1].config.mtu", func(c *Config) { c.Channels[1].Config["mtu"] = 575 }},
		{"MTU high", "channels[1].config.mtu", func(c *Config) { c.Channels[1].Config["mtu"] = 9001 }},
		{"unknown config", "channels[1].config", func(c *Config) { c.Channels[1].Config["unknown"] = true }},
		{"unencodable config", "channels[1].config", func(c *Config) { c.Channels[1].Config["mtu"] = func() {} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validOpenConnectConfig()
			test.edit(cfg)
			if !hasErrorAt(cfg.Validate(), test.path) {
				t.Fatalf("invalid OpenConnect accepted; expected %s: %+v", test.path, cfg.Validate().Problems)
			}
		})
	}
}
