package api

import (
	"reflect"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestXrayOutboundCredentialAliasesRoundTrip(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess", "socks", "http", "hysteria"} {
		t.Run(protocol, func(t *testing.T) {
			original := config.Default()
			original.Channels = []config.Channel{{ID: "channel-id", Type: "xray", Config: map[string]any{
				"outbound": map[string]any{"protocol": protocol, "tag": "public-tag",
					"settings": map[string]any{"address": "example.com", "id": "credential-id", "pass": "credential-pass",
						"vnext": []any{map[string]any{"address": "example.com", "users": []any{map[string]any{"id": "nested-credential", "email": "label"}}}}},
					"streamSettings": map[string]any{"hysteriaSettings": map[string]any{"auth": "credential-auth"}}},
				"peers": []any{map[string]any{"id": "structural-id", "password": "peer-secret"}},
			}}}
			visible, err := redactAdminConfig(original)
			if err != nil {
				t.Fatal(err)
			}
			out := visible.Channels[0].Config["outbound"].(map[string]any)
			settings := out["settings"].(map[string]any)
			user := settings["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
			auth := out["streamSettings"].(map[string]any)["hysteriaSettings"].(map[string]any)
			if settings["id"] != "" || settings["pass"] != "" || user["id"] != "" || auth["auth"] != "" {
				t.Fatal("stored outbound credential returned to browser")
			}
			if visible.Channels[0].ID != "channel-id" || visible.Channels[0].Config["peers"].([]any)[0].(map[string]any)["id"] != "structural-id" || out["tag"] != "public-tag" {
				t.Fatal("structural identity redacted")
			}
			mergeRedactedSecrets(visible, original)
			if !reflect.DeepEqual(visible, original) {
				t.Fatal("redacted round trip changed credentials")
			}
			settings["id"] = "replacement"
			mergeRedactedSecrets(visible, original)
			if settings["id"] != "replacement" {
				t.Fatal("explicit replacement lost")
			}
		})
	}
}

func TestRedactedXrayUsersFollowEmailWhenReordered(t *testing.T) {
	users := func(rows ...any) map[string]any {
		return map[string]any{"outbound": map[string]any{"settings": map[string]any{
			"vnext": []any{map[string]any{"users": rows}},
		}}}
	}
	previous := users(map[string]any{"email": "alice", "id": "alice-secret"}, map[string]any{"email": "bob", "id": "bob-secret"})
	next := users(map[string]any{"email": "bob", "id": ""}, map[string]any{"email": "alice", "id": ""})
	mergeSecretMap(next, previous)
	got := next["outbound"].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)
	if got[0].(map[string]any)["id"] != "bob-secret" || got[1].(map[string]any)["id"] != "alice-secret" {
		t.Fatal("reordering redacted Xray users exchanged their credentials")
	}
}
