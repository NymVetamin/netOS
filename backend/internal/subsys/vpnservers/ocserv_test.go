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
