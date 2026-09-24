package api

import (
	"testing"

	"github.com/netos-router/netos/internal/config"
)

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
