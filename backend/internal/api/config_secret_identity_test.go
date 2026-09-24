package api

import "testing"

func TestMergeSecretMapFollowsNestedIdentity(t *testing.T) {
	previous := map[string]any{"peers": []any{
		map[string]any{"id": "a", "password": "secret-a"},
		map[string]any{"id": "b", "password": "secret-b"},
	}}
	next := map[string]any{"peers": []any{
		map[string]any{"id": "b", "password": ""},
		map[string]any{"id": "a", "password": ""},
		map[string]any{"id": "new", "password": ""},
	}}
	mergeSecretMap(next, previous)
	peers := next["peers"].([]any)
	for index, want := range []string{"secret-b", "secret-a", ""} {
		if got := peers[index].(map[string]any)["password"]; got != want {
			t.Fatalf("peer %d received %q, want %q", index, got, want)
		}
	}
}
