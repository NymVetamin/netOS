package api

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestSecretPresenceRoundTrip(t *testing.T) {
	cfg := config.Default()
	cfg.DDNS.Password = "ddns-credential"
	cfg.WANs = []config.WAN{{ID: "wan", Password: "wan-credential"}, {ID: "empty"}}
	cfg.WiFi = []config.WiFiRadio{{ID: "radio", SSIDs: []config.WiFiSSID{{ID: "ssid", Password: "wifi-credential"}}}}
	cfg.Samba.Users = []config.SambaUser{{ID: "alice", Password: "smb-credential"}}
	cfg.VPNServers = []config.VPNServer{{ID: "vpn", Type: "wireguard", Config: map[string]any{"private_key": "wg-credential", "preshared_key": ""}, Peers: []config.VPNPeer{{ID: "client", Credentials: map[string]string{"password": "peer-credential", "uuid": "", "username": "alice"}}}}}
	cfg.Channels = []config.Channel{{ID: "xray", Config: map[string]any{"outbound": map[string]any{"settings": map[string]any{"vnext": []any{map[string]any{"users": []any{map[string]any{"id": "xray-credential", "email": "alice"}}}}}}}}}
	visible, err := redactAdminConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for name, pair := range map[string]struct{ got, want map[string]bool }{
		"ddns":   {visible.DDNS.SecretsSet, map[string]bool{"password": true}},
		"wan":    {visible.WANs[0].SecretsSet, map[string]bool{"password": true}},
		"wifi":   {visible.WiFi[0].SSIDs[0].SecretsSet, map[string]bool{"password": true}},
		"samba":  {visible.Samba.Users[0].SecretsSet, map[string]bool{"password": true}},
		"server": {visible.VPNServers[0].SecretsSet, map[string]bool{"private_key": true}},
		"peer":   {visible.VPNServers[0].Peers[0].SecretsSet, map[string]bool{"password": true}},
		"xray":   {visible.Channels[0].SecretsSet, map[string]bool{"outbound.settings.vnext[0].users[0].id": true}},
	} {
		if !reflect.DeepEqual(pair.got, pair.want) {
			t.Errorf("%s presence = %v, want %v", name, pair.got, pair.want)
		}
	}
	if len(visible.WANs[1].SecretsSet) != 0 {
		t.Fatal("empty password shown as saved")
	}
	data, _ := json.Marshal(visible)
	if strings.Contains(string(data), "-credential") {
		t.Fatal("secret leaked into read response")
	}
	if len(cfg.DDNS.SecretsSet) != 0 || cfg.DDNS.Password != "ddns-credential" {
		t.Fatal("redaction mutated source")
	}
	mergeRedactedSecrets(visible, cfg)
	if !reflect.DeepEqual(visible, cfg) {
		t.Fatal("roundtrip changed config or retained response metadata")
	}
	visible, _ = redactAdminConfig(cfg)
	visible.WANs[0], visible.WANs[1] = visible.WANs[1], visible.WANs[0]
	visible.DDNS.Password = "replacement"
	visible.DDNS.SecretsSet = map[string]bool{"token": true}
	mergeRedactedSecrets(visible, cfg)
	if visible.WANs[0].Password != "" || visible.WANs[1].Password != "wan-credential" || visible.DDNS.Password != "replacement" {
		t.Fatal("reorder or password replacement failed")
	}
	if visible.DDNS.SecretsSet != nil {
		t.Fatal("client-supplied presence persisted")
	}
	reloaded, _ := redactAdminConfig(visible)
	if !reloaded.DDNS.SecretsSet["password"] || reloaded.DDNS.SecretsSet["token"] {
		t.Fatal("reload trusted stale metadata")
	}
}
