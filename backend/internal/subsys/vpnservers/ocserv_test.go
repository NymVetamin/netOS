package vpnservers

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func ocservConfig() (*config.Config, config.VPNServer) {
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "ocserv", Installed: true}}
	server := config.VPNServer{
		ID: "openconnect", Index: 3, Name: "OpenConnect", Enabled: true, Type: "ocserv",
		Subnet: "10.30.0.1/24", Port: 4443, DefaultChannel: "direct",
		Config: map[string]any{"public_endpoint": "vpn.example.com:4443", "dns": []string{"10.30.0.1"}, "mtu": 1380, "banner": "netOS VPN"},
		Peers:  []config.VPNPeer{{ID: "phone", Name: "Phone", Enabled: true, Address: "10.30.0.2", Credentials: map[string]string{"username": "phone", "password": "strong-password"}}},
	}
	cfg.VPNServers = []config.VPNServer{server}
	return cfg, server
}

func TestRenderOcserv(t *testing.T) {
	cfg, server := ocservConfig()
	out, err := RenderOcserv(server, cfg, "/var/lib/netos/generated")
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{
		"auth = \"plain[passwd=/var/lib/netos/generated/ocserv-srv3.passwd]\"",
		"tcp-port = 4443", "udp-port = 4443", "device = vpns3", "ipv4-network = 10.30.0.0/24",
		"config-per-user = /var/lib/netos/generated/ocserv-srv3-users", "dns = 10.30.0.1", "route = default",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("render lacks %q:\n%s", want, text)
		}
	}
}

func TestOcservValidation(t *testing.T) {
	cfg, _ := ocservConfig()
	for _, p := range cfg.Validate().Problems {
		if p.Severity == "error" {
			t.Fatalf("valid ocserv config rejected: %+v", p)
		}
	}
	cfg.VPNServers[0].Peers[0].Credentials["username"] = "../../root"
	if !cfg.Validate().HasErrors() {
		t.Fatal("unsafe ocserv username accepted")
	}
}

func TestOcservRouterDNS(t *testing.T) {
	for _, tc := range []struct {
		name, subnet, dns string
		routes            []string
		addRoute          bool
	}{
		{"full", "10.30.0.1/24", "10.30.0.1", nil, false},
		{"split", "10.30.0.1/24", "10.30.0.1", []string{"192.0.2.0/24"}, true},
		{"covered", "10.30.0.1/24", "10.30.0.1", []string{"10.30.0.0/24"}, false},
		{"changed subnet", "10.40.0.1/24", "10.40.0.1", nil, false},
		{"non-first host", "10.30.0.9/24", "10.30.0.1", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, server := ocservConfig()
			server.Subnet = tc.subnet
			server.Config["use_router_dns"] = true
			server.Config["dns"] = []string{"9.9.9.9"}
			server.Config["routes"] = tc.routes
			out, err := RenderOcserv(server, cfg, "/generated")
			if err != nil {
				t.Fatal(err)
			}
			text := string(out)
			if !strings.Contains(text, "dns = "+tc.dns+"\n") || strings.Contains(text, "dns = 9.9.9.9") {
				t.Fatalf("incorrect router DNS:\n%s", text)
			}
			if strings.Contains(text, "route = "+tc.dns+"/32\n") != tc.addRoute {
				t.Fatal("split tunnel DNS route missing or duplicated")
			}
			server.Config["use_router_dns"] = false
			out, err = RenderOcserv(server, cfg, "/generated")
			if err != nil || !strings.Contains(string(out), "dns = 9.9.9.9\n") {
				t.Fatal("custom DNS lost when switch disabled")
			}
		})
	}
	cfg, _ := ocservConfig()
	cfg.VPNServers[0].Config["use_router_dns"] = true
	if cfg.Validate().HasErrors() {
		t.Fatal("router DNS option rejected by validation")
	}
}
