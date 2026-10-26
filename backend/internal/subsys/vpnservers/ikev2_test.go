package vpnservers

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestIKEv2ConfigChangeRestartsInsteadOfReloadingLivePool(t *testing.T) {
	s, _ := newTestSubsystem(t)
	s.UnitDir = filepath.Join(t.TempDir(), "units")
	runner := &vpnServiceRunner{active: map[string]bool{}, s: s}
	s.Runner = runner
	cfg, server := ikev2TestConfig()
	if err := s.applyIKEv2(context.Background(), cfg, []config.VPNServer{server}, false); err != nil {
		t.Fatal(err)
	}

	runner.commands = nil
	updated := server
	updated.Peers = append([]config.VPNPeer(nil), server.Peers...)
	updated.Peers[0].Credentials = map[string]string{"username": "bob", "password": "bob-secret"}
	if err := s.applyIKEv2(context.Background(), cfg, []config.VPNServer{updated}, true); err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(runner.commands, "\n")
	if strings.Contains(commands, "/usr/sbin/swanctl --load-all") {
		t.Fatalf("changed IKEv2 pool was loaded into the live daemon:\n%s", commands)
	}
	if strings.Count(commands, "systemctl restart "+ikev2Unit) != 1 {
		t.Fatalf("changed IKEv2 configuration did not restart the daemon exactly once:\n%s", commands)
	}
}

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
		"netos-srv4", "pools = radius", "id = vpn.example.test", "auth = eap-radius",
		"local_ts = 10.0.0.0/8", "if_id_in = 50004", "if_id_out = 50004", "groups = netos-srv4",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("render lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "alice-secret") {
		t.Fatal("plaintext password leaked into rendered config")
	}
}

func TestIKEv2ChannelDoesNotChangeServerRuntime(t *testing.T) {
	cfg, server := ikev2TestConfig()
	next := server
	next.Name = "Renamed IKEv2"
	next.DefaultChannel = "alternate"
	next.Peers = append([]config.VPNPeer(nil), server.Peers...)
	next.Peers[0].Channel = "alternate"
	before, err := RenderIKEv2([]config.VPNServer{server}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	after, err := RenderIKEv2([]config.VPNServer{next}, cfg)
	if err != nil || string(before) != string(after) {
		t.Fatalf("channel changed runtime config: %v", err)
	}
	if !sameServerRuntime(server, next) {
		t.Fatal("channel-only edit plans server update")
	}
	if next.Peers[0].Channel != "alternate" {
		t.Fatal("comparison mutated config")
	}
	next.Peers[0].Credentials = map[string]string{"username": "alice", "password": "changed-secret"}
	if sameServerRuntime(server, next) {
		t.Fatal("credential change ignored")
	}
}

func TestRenderIKEv2MultiUserAddressesBelongToAuthenticatedAccounts(t *testing.T) {
	cfg, server := ikev2TestConfig()
	server.Peers = append(server.Peers, config.VPNPeer{
		ID: "bob", Name: "Bob", Enabled: true, Address: "10.40.0.4",
		Credentials: map[string]string{"username": "bob", "password": "bob-secret"},
	})
	out, err := RenderIKEv2([]config.VPNServer{server}, cfg)
	if err != nil || strings.Contains(string(out), "addrs = 10.40.") {
		t.Fatalf("multiuser server must not allocate an unauthenticated pool: %s, %v", out, err)
	}
	users, err := renderIKEv2AuthUsers([]config.VPNServer{server})
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range server.Peers {
		want := fmt.Sprintf("\"%s\" NT-Password := 0x%s\n    Framed-IP-Address = %s,", peer.Credentials["username"], ikev2NTPassword(peer.Credentials["password"]), peer.Address)
		if !strings.Contains(string(users), want) {
			t.Fatalf("missing account/IP binding: %s", users)
		}
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

func TestIKEv2SplitRoutesIncludePushedDNS(t *testing.T) {
	cfg, server := ikev2TestConfig()
	server.Config["split_routes"] = []string{"192.0.3.0/24"}
	server.Config["dns"] = []string{"10.40.0.1"}
	out, err := RenderIKEv2([]config.VPNServer{server}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "local_ts = 192.0.3.0/24, 10.40.0.1/32") {
		t.Fatal("DNS omitted from traffic selectors")
	}
	users, err := renderIKEv2AuthUsers([]config.VPNServer{server})
	if err != nil || !strings.Contains(string(users), `CVPN3000-IPSec-Split-Tunnel-List = "192.0.3.0/24,10.40.0.1/32"`) {
		t.Fatalf("DNS omitted from split attributes: %s, %v", users, err)
	}
}
