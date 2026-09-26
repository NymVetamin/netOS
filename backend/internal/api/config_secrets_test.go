package api

import (
	"reflect"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestAdminConfigRedactsXrayCredentialsRoundTrip(t *testing.T) {
	original := config.Default()
	original.Channels = []config.Channel{{ID: "xray", Type: "xray", Config: map[string]any{
		"outbound": map[string]any{"streamSettings": map[string]any{"realitySettings": map[string]any{"shortId": "abcd", "publicKey": "public"}}},
	}}}
	original.VPNServers = []config.VPNServer{{ID: "vless", Type: "xray", Peers: []config.VPNPeer{
		{ID: "alice", Credentials: map[string]string{"uuid": "alice-credential", "username": "alice"}},
		{ID: "bob", Credentials: map[string]string{"uuid": "bob-credential", "username": "bob"}},
	}}}
	visible, err := redactAdminConfig(original)
	if err != nil {
		t.Fatal(err)
	}
	reality := visible.Channels[0].Config["outbound"].(map[string]any)["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
	if reality["shortId"] != "" || visible.VPNServers[0].Peers[0].Credentials["uuid"] != "" {
		t.Fatal("Xray credentials were returned to the browser")
	}
	if reality["publicKey"] != "public" {
		t.Fatal("public key was hidden")
	}
	mergeRedactedSecrets(visible, original)
	if !reflect.DeepEqual(visible, original) {
		t.Fatal("round trip changed stored credentials")
	}
	visible.VPNServers[0].Peers[0], visible.VPNServers[0].Peers[1] = visible.VPNServers[0].Peers[1], visible.VPNServers[0].Peers[0]
	visible.VPNServers[0].Peers[0].Credentials["uuid"] = ""
	visible.VPNServers[0].Peers[1].Credentials["uuid"] = "replacement"
	mergeRedactedSecrets(visible, original)
	if visible.VPNServers[0].Peers[0].Credentials["uuid"] != "bob-credential" || visible.VPNServers[0].Peers[1].Credentials["uuid"] != "replacement" {
		t.Fatal("peer reorder or explicit credential replacement was lost")
	}
}

func TestAdminConfigRedactsSecretsAndPreservesThemOnSave(t *testing.T) {
	original := config.Default()
	original.Channels = append(original.Channels, config.Channel{ID: "wg", Type: "wireguard", Config: map[string]any{
		"private_key": "private", "preshared_key": "psk", "peer_public_key": "public",
	}})
	original.VPNServers = []config.VPNServer{{ID: "oc", Type: "ocserv", Peers: []config.VPNPeer{{ID: "peer", Credentials: map[string]string{"username": "alice", "password": "secret"}}}}}
	visible, err := redactAdminConfig(original)
	if err != nil {
		t.Fatal(err)
	}
	if visible.Channels[1].Config["private_key"] != "" || visible.Channels[1].Config["preshared_key"] != "" || visible.VPNServers[0].Peers[0].Credentials["password"] != "" {
		t.Fatal("secret was returned to administrator")
	}
	if visible.Channels[1].Config["peer_public_key"] != "public" || visible.VPNServers[0].Peers[0].Credentials["username"] != "alice" {
		t.Fatal("nonsecret editing fields disappeared")
	}
	visible.System.Hostname = "renamed"
	mergeRedactedSecrets(visible, original)
	if visible.Channels[1].Config["private_key"] != "private" || visible.Channels[1].Config["preshared_key"] != "psk" || visible.VPNServers[0].Peers[0].Credentials["password"] != "secret" {
		t.Fatal("saving an unrelated change erased stored credentials")
	}
	if original.System.Hostname == "renamed" {
		t.Fatal("merge changed the stored configuration")
	}
}
