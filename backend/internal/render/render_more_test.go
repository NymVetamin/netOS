package render

import (
	"reflect"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestCatalogLookupAndCopiesCannotMutateRegistry(t *testing.T) {
	want := IDs()
	if len(want) == 0 {
		t.Fatal("empty artifact catalog")
	}
	if got := IDs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("unstable IDs: %v != %v", got, want)
	}

	copyOfCatalog := All()
	copyOfCatalog[0].ID = "corrupted"
	copyOfIDs := IDs()
	copyOfIDs[0] = "corrupted"
	if got := IDs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("caller mutated the shared catalog: %v", got)
	}

	seen := make(map[string]bool, len(want))
	for _, id := range want {
		if seen[id] {
			t.Errorf("duplicate artifact ID %q", id)
		}
		seen[id] = true
		a, ok := ByID(id)
		if !ok || a.ID != id || a.Title == "" || a.Active == nil || a.Render == nil {
			t.Errorf("incomplete lookup result for %q: %+v, ok=%v", id, a, ok)
		}
	}
	if _, ok := ByID("missing"); ok {
		t.Fatal("unknown artifact found")
	}
	if _, err := Render("missing", config.Default()); err == nil {
		t.Fatal("unknown artifact rendered without an error")
	}
}

func TestConditionalArtifactsIgnoreDisabledAndOtherKinds(t *testing.T) {
	cfg := config.Default()
	cfg.Channels = []config.Channel{
		{Enabled: false, Type: "wireguard"},
		{Enabled: true, Type: "direct"},
		{Enabled: false, Type: "xray"},
	}
	cfg.WiFi = []config.WiFiRadio{{Enabled: false}}
	cfg.VPNServers = []config.VPNServer{
		{Enabled: false, Type: "xray"},
		{Enabled: false, Type: "ocserv"},
		{Enabled: false, Type: "ikev2"},
		{Enabled: true, Type: "wireguard"},
	}
	for _, id := range []string{"wireguard", "xray", "xray-servers", "hostapd", "ocserv", "strongswan"} {
		if has(ids(Active(cfg)), id) {
			t.Errorf("inactive artifact %q reported active", id)
		}
		out, err := Render(id, cfg)
		if err != nil || strings.TrimSpace(out) == "" {
			t.Errorf("inactive artifact %q must return explanatory output: %q, %v", id, out, err)
		}
	}
}

func TestConditionalArtifactsRenderEnabledInstances(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "br0", Type: "bridge", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "office", Interface: "lan", RouterAddress: "192.168.50.1/24", Enabled: true}}
	cfg.Channels = []config.Channel{{
		ID: "wg", Index: 3, Name: "WG", Enabled: true, Type: "wireguard",
		Config: map[string]any{
			"address": "10.9.0.2/32", "private_key": "private", "peer_public_key": "public",
			"preshared_key": "shared", "endpoint": "vpn.example:51820",
			"allowed_ips": []string{"0.0.0.0/0"}, "persistent_keepalive": 25,
		},
	}}
	cfg.WiFi = []config.WiFiRadio{{
		ID: "phy0", Device: "wlan0", Enabled: true, Band: "5", Channel: 36, Width: 80, Country: "ru",
		SSIDs: []config.WiFiSSID{{ID: "main", SSID: "Office", Enabled: true, Security: "wpa2", Password: "password1", Network: "office"}},
	}}
	cfg.VPNServers = []config.VPNServer{
		{ID: "oc", Index: 4, Name: "OC", Enabled: true, Type: "ocserv", Port: 443, Subnet: "10.40.0.1/24", Config: map[string]any{"dns": []string{"1.1.1.1"}}},
		{ID: "ike", Index: 5, Name: "IKE", Enabled: true, Type: "ikev2", Port: 500, Subnet: "10.50.0.1/24", Config: map[string]any{"server_identity": "vpn.example"}, Peers: []config.VPNPeer{{Enabled: true, Address: "10.50.0.2", Credentials: map[string]string{"username": "alice", "password": "secret"}}}},
	}

	cases := map[string][]string{
		"wireguard":  {"wg-ch3", "PrivateKey = private", "PersistentKeepalive = 25"},
		"hostapd":    {"interface=wlan0", "ssid=Office", "bridge=br0"},
		"ocserv":     {"TCP/UDP 443", "device = vpns4", "dns = 1.1.1.1"},
		"strongswan": {"netos-srv5", "id = vpn.example", "id = alice"},
	}
	active := ids(Active(cfg))
	for id, fragments := range cases {
		if !has(active, id) {
			t.Errorf("enabled artifact %q is not active: %v", id, active)
		}
		out, err := Render(id, cfg)
		if err != nil {
			t.Errorf("render %s: %v", id, err)
			continue
		}
		for _, fragment := range fragments {
			if !strings.Contains(out, fragment) {
				t.Errorf("render %s lacks %q:\n%s", id, fragment, out)
			}
		}
	}
}

func TestConditionalRenderersPropagateInvalidConfiguration(t *testing.T) {
	cases := []struct {
		id     string
		mutate func(*config.Config)
	}{
		{"wireguard", func(cfg *config.Config) {
			cfg.Channels = []config.Channel{{Enabled: true, Type: "wireguard", Config: map[string]any{"unknown": true}}}
		}},
		{"xray", func(cfg *config.Config) {
			cfg.Channels = []config.Channel{{Enabled: true, Type: "xray", Config: map[string]any{"unknown": true}}}
		}},
		{"xray-servers", func(cfg *config.Config) {
			cfg.VPNServers = []config.VPNServer{{Enabled: true, Type: "xray", Config: map[string]any{"unknown": true}}}
		}},
		{"hostapd", func(cfg *config.Config) { cfg.WiFi = []config.WiFiRadio{{Enabled: true}} }},
		{"ocserv", func(cfg *config.Config) {
			cfg.VPNServers = []config.VPNServer{{Enabled: true, Type: "ocserv", Subnet: "invalid"}}
		}},
		{"strongswan", func(cfg *config.Config) {
			cfg.VPNServers = []config.VPNServer{{Enabled: true, Type: "ikev2", Config: map[string]any{"unknown": true}}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			cfg := config.Default()
			tc.mutate(cfg)
			if _, err := Render(tc.id, cfg); err == nil {
				t.Fatal("invalid configuration rendered without an error")
			}
		})
	}
}
