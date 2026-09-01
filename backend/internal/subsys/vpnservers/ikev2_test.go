package vpnservers

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func ikev2TestConfig() (*config.Config, config.VPNServer) {
	cfg := config.Default()
	cfg.System.Hostname = "router.example.test"
	cfg.Components = []config.Component{{ID: "strongswan", Installed: true}}
	server := config.VPNServer{
		ID: "ike", Index: 4, Name: "IKEv2", Enabled: true, Type: "ikev2", Subnet: "10.40.0.1/24", Port: 500, DefaultChannel: "direct",
		Config: map[string]any{"public_endpoint": "vpn.example.test", "server_identity": "vpn.example.test", "dns": []string{"10.40.0.1"}, "split_routes": []string{"10.0.0.0/8"}, "mtu": 1400},
		Peers: []config.VPNPeer{
			{ID: "alice", Name: "Alice", Enabled: true, Address: "10.40.0.2", Credentials: map[string]string{"username": "alice", "password": "alice-secret"}},
		},
	}
	cfg.VPNServers = []config.VPNServer{server}
	return cfg, server
}

func TestRenderIKEv2(t *testing.T) {
	cfg, server := ikev2TestConfig()
	out, err := RenderIKEv2([]config.VPNServer{server}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{
		"netos-srv4", "pools = netos-srv4", "id = vpn.example.test", "auth = eap-mschapv2",
		"local_ts = 10.0.0.0/8", "if_id_out = 50004", "addrs = 10.40.0.2",
		"dns = 10.40.0.1", "id = alice", "secret = 0s",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("render lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "alice-secret") {
		t.Fatal("plaintext password leaked into rendered config")
	}
}

func TestRenderIKEv2RejectsAmbiguousMultiUserPool(t *testing.T) {
	cfg, server := ikev2TestConfig()
	server.Peers = append(server.Peers, config.VPNPeer{
		ID: "bob", Name: "Bob", Enabled: true, Address: "10.40.0.4",
		Credentials: map[string]string{"username": "bob", "password": "bob-secret"},
	})
	if _, err := RenderIKEv2([]config.VPNServer{server}, cfg); err == nil || !strings.Contains(err.Error(), "только одного активного пользователя") {
		t.Fatalf("ambiguous IKEv2 pool was accepted: %v", err)
	}
}

func TestIKEv2Validation(t *testing.T) {
	cfg, _ := ikev2TestConfig()
	if result := cfg.Validate(); result.HasErrors() {
		t.Fatalf("valid IKEv2 server rejected: %+v", result.Problems)
	}
	cfg.VPNServers[0].Config["server_identity"] = "bad\nidentity"
	if !cfg.Validate().HasErrors() {
		t.Fatal("unsafe IKEv2 identity accepted")
	}
}
