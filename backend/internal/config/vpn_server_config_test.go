package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func validWGServerConfig() *Config {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg := Default()
	cfg.Components = []Component{{ID: "wireguard", Installed: true}}
	cfg.VPNServers = []VPNServer{{
		ID: "srv", Index: 1, Name: "VPN", Enabled: true, Type: "wireguard", Subnet: "10.9.0.1/24", Port: 51820,
		Config: map[string]any{"private_key": key, "client_allowed_ips": []string{"0.0.0.0/0"}},
		Peers:  []VPNPeer{{ID: "phone", Name: "Phone", Enabled: true, Address: "10.9.0.2", Credentials: map[string]string{"public_key": key}}},
	}}
	return cfg
}

func TestWireGuardServerValidation(t *testing.T) {
	cfg := validWGServerConfig()
	if result := cfg.Validate(); result.HasErrors() {
		t.Fatalf("валидный сервер отклонён: %+v", result.Problems)
	}
	cfg.VPNServers[0].Peers[0].Address = "10.10.0.2"
	result := cfg.Validate()
	for _, problem := range result.Problems {
		if strings.Contains(problem.Path, "peers[0].address") {
			return
		}
	}
	t.Fatalf("адрес вне подсети принят: %+v", result.Problems)
}

func TestWireGuardServerRequiresComponent(t *testing.T) {
	cfg := validWGServerConfig()
	cfg.Components = nil
	for _, problem := range cfg.Validate().Problems {
		if problem.Path == "vpn_servers[0].enabled" {
			return
		}
	}
	t.Fatal("сервер без компонента WireGuard принят")
}

func TestDisabledVPNServerMayBeSavedAsIncompleteDraft(t *testing.T) {
	cfg := Default()
	cfg.VPNServers = []VPNServer{{
		ID: "draft", Index: 1, Name: "Draft", Type: "wireguard", Subnet: "10.9.0.1/24", Port: 51820,
		Config: map[string]any{"private_key": "", "mtu": 1420},
	}}
	if result := cfg.Validate(); result.HasErrors() {
		t.Fatalf("disabled draft rejected: %+v", result.Problems)
	}
	cfg.VPNServers[0].Enabled = true
	if result := cfg.Validate(); !result.HasErrors() {
		t.Fatal("enabled server with an empty key was accepted")
	}
}

func TestXrayServerValidation(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	cfg := Default()
	cfg.Components = []Component{{ID: "xray", Installed: true}}
	cfg.VPNServers = []VPNServer{{
		ID: "reality", Index: 2, Name: "Reality", Enabled: true, Type: "xray",
		Subnet: "10.10.0.1/24", Port: 443, DefaultChannel: "direct",
		Config: map[string]any{
			"private_key": key, "destination": "www.example.com:443",
			"server_names": []string{"www.example.com"}, "short_ids": []string{"0123456789abcdef"},
		},
		Peers: []VPNPeer{{ID: "phone", Name: "Phone", Enabled: true, Address: "10.10.0.2", Credentials: map[string]string{"uuid": "123e4567-e89b-12d3-a456-426614174000"}}},
	}}
	if result := cfg.Validate(); result.HasErrors() {
		t.Fatalf("valid Xray server rejected: %+v", result.Problems)
	}
	cfg.VPNServers[0].Config["short_ids"] = []string{"not-hex"}
	for _, problem := range cfg.Validate().Problems {
		if problem.Path == "vpn_servers[0].config.short_ids[0]" {
			return
		}
	}
	t.Fatal("invalid Reality short ID accepted")
}

func TestVPNServerValidationRejectsUnsafeGenericFields(t *testing.T) {
	tests := []struct {
		name string
		path string
		edit func(*Config)
	}{
		{"unit-name-injection", "vpn_servers[0].name", func(c *Config) { c.VPNServers[0].Name = "VPN\nExecStart=/bin/evil" }},
		{"network-as-server", "vpn_servers[0].subnet", func(c *Config) { c.VPNServers[0].Subnet = "10.9.0.0/24" }},
		{"tiny-subnet", "vpn_servers[0].subnet", func(c *Config) { c.VPNServers[0].Subnet = "10.9.0.1/31" }},
		{"duplicate-peer-id", "vpn_servers[0].peers[1].id", func(c *Config) {
			c.VPNServers[0].Peers = append(c.VPNServers[0].Peers, c.VPNServers[0].Peers[0])
			c.VPNServers[0].Peers[1].Address = "10.9.0.3"
		}},
		{"server-address-as-peer", "vpn_servers[0].peers[0].address", func(c *Config) { c.VPNServers[0].Peers[0].Address = "10.9.0.1" }},
		{"broadcast-as-peer", "vpn_servers[0].peers[0].address", func(c *Config) { c.VPNServers[0].Peers[0].Address = "10.9.0.255" }},
		{"ipv6-peer", "vpn_servers[0].peers[0].address", func(c *Config) { c.VPNServers[0].Peers[0].Address = "2001:db8::1" }},
		{"endpoint-injection", "vpn_servers[0].config.public_endpoint", func(c *Config) { c.VPNServers[0].Config["public_endpoint"] = "vpn.example\nAddress=evil:51820" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validWGServerConfig()
			tt.edit(cfg)
			if !hasErrorAt(cfg.Validate(), tt.path) {
				t.Fatalf("unsafe VPN configuration accepted; expected %s: %#v", tt.path, cfg.Validate().Problems)
			}
		})
	}
}

func TestXrayServerValidationRejectsInvalidNamesAndFlow(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	base := func() *Config {
		cfg := Default()
		cfg.Components = []Component{{ID: "xray", Installed: true}}
		cfg.VPNServers = []VPNServer{{
			ID: "reality", Index: 2, Name: "Reality", Enabled: true, Type: "xray", Subnet: "10.10.0.1/24", Port: 443,
			Config: map[string]any{"private_key": key, "destination": "www.example.com:443", "server_names": []string{"www.example.com"}, "short_ids": []string{"0123456789abcdef"}, "flow": "xtls-rprx-vision"},
			Peers:  []VPNPeer{{ID: "phone", Address: "10.10.0.2", Enabled: true, Credentials: map[string]string{"uuid": "123e4567-e89b-12d3-a456-426614174000"}}},
		}}
		return cfg
	}
	for _, tt := range []struct {
		path string
		edit func(*Config)
	}{
		{"vpn_servers[0].config.destination", func(c *Config) { c.VPNServers[0].Config["destination"] = "bad name:443" }},
		{"vpn_servers[0].config.server_names[0]", func(c *Config) { c.VPNServers[0].Config["server_names"] = []string{"bad name"} }},
		{"vpn_servers[0].config.server_names[1]", func(c *Config) {
			c.VPNServers[0].Config["server_names"] = []string{"www.example.com", "WWW.EXAMPLE.COM"}
		}},
		{"vpn_servers[0].config.short_ids[1]", func(c *Config) { c.VPNServers[0].Config["short_ids"] = []string{"aabb", "AABB"} }},
		{"vpn_servers[0].config.flow", func(c *Config) { c.VPNServers[0].Config["flow"] = "unsupported" }},
	} {
		cfg := base()
		tt.edit(cfg)
		if !hasErrorAt(cfg.Validate(), tt.path) {
			t.Errorf("invalid Xray setting accepted at %s: %#v", tt.path, cfg.Validate().Problems)
		}
	}
}

func TestVPNServerPortConflictsRespectTransport(t *testing.T) {
	cfg := validWGServerConfig()
	key := cfg.VPNServers[0].Config["private_key"]
	// TCP Xray and UDP WireGuard may intentionally share a number.
	cfg.VPNServers = append(cfg.VPNServers, VPNServer{
		ID: "xray", Index: 2, Name: "Xray", Enabled: true, Type: "xray", Subnet: "10.10.0.1/24", Port: 51820,
		Config: map[string]any{"private_key": base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "destination": "www.example.com:443", "server_names": []string{"www.example.com"}, "short_ids": []string{"aabb"}},
		Peers:  []VPNPeer{{ID: "x", Address: "10.10.0.2", Enabled: true, Credentials: map[string]string{"uuid": "123e4567-e89b-12d3-a456-426614174000"}}},
	})
	cfg.Components = append(cfg.Components, Component{ID: "xray", Installed: true})
	if result := cfg.Validate(); hasErrorAt(result, "vpn_servers[1].port") {
		t.Fatalf("TCP and UDP on the same number incorrectly conflict: %#v (key=%v)", result.Problems, key)
	}

	// Ocserv claims both transports and therefore conflicts with both.
	cfg.VPNServers = append(cfg.VPNServers, VPNServer{
		ID: "oc", Index: 3, Name: "OC", Enabled: true, Type: "ocserv", Subnet: "10.11.0.1/24", Port: 51820,
		Config: map[string]any{"mtu": 1380}, Peers: []VPNPeer{{ID: "u", Address: "10.11.0.2", Enabled: true, Credentials: map[string]string{"username": "user", "password": "long-password"}}},
	})
	cfg.Components = append(cfg.Components, Component{ID: "ocserv", Installed: true})
	if !hasErrorAt(cfg.Validate(), "vpn_servers[2].port") {
		t.Fatal("ocserv port collision accepted")
	}
}

func TestVPNServerPortsCannotCollideWithSystemListeners(t *testing.T) {
	for _, port := range []int{53, 500, 4500} {
		cfg := validWGServerConfig()
		cfg.VPNServers[0].Port = port
		if port == 53 {
			cfg.DNS.Enabled, cfg.DNS.Provider = true, "dnsmasq"
			cfg.Components = append(cfg.Components, Component{ID: "dnsmasq", Installed: true})
		}
		if port == 500 || port == 4500 {
			cfg.Components = append(cfg.Components, Component{ID: "strongswan", Installed: true})
			cfg.VPNServers = append(cfg.VPNServers, VPNServer{
				ID: "ike", Index: 2, Name: "IKE", Enabled: true, Type: "ikev2", Subnet: "10.12.0.1/24", Port: 500,
				Config: map[string]any{"public_endpoint": "vpn.example", "server_identity": "vpn.example", "mtu": 1400},
			})
		}
		if !hasErrorAt(cfg.Validate(), "vpn_servers") {
			t.Errorf("system UDP port %d collision accepted", port)
		}
	}
}
