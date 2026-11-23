package api

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func previousSecretMatch(child map[string]any, old []any, index int, skipID bool) map[string]any {
	for _, field := range []string{"id", "name", "email"} {
		if field == "id" && skipID {
			continue
		}
		identity, ok := child[field].(string)
		if !ok || identity == "" {
			continue
		}
		for _, item := range old {
			if m, ok := item.(map[string]any); ok && m[field] == identity {
				return m
			}
		}
		return nil
	}
	if index < len(old) {
		m, _ := old[index].(map[string]any)
		return m
	}
	return nil
}

func TestNestedSecretMergePreservesIdentityRules(t *testing.T) {
	old := []any{
		map[string]any{"id": "a", "name": "n", "email": "e", "password": "first"},
		map[string]any{"id": "a", "name": "n", "email": "e", "password": "second"},
		42,
		map[string]any{"id": "b", "name": "other", "email": "different", "password": "third"},
	}
	for range len(old) {
		for _, path := range []string{"", "outbound.settings"} {
			for range 2 {
				children := []any{map[string]any{"id": "a", "password": ""}, map[string]any{"id": "missing", "name": "n", "password": ""}, map[string]any{"password": ""}, map[string]any{"id": 42, "email": "different", "password": ""}, map[string]any{"name": "n", "password": "explicit"}, map[string]any{"name": "", "email": "e", "password": ""}, "non-map", map[string]any{"password": ""}}
				skipID := path != ""
				want := make([]string, len(children))
				for i, item := range children {
					if m, ok := item.(map[string]any); ok {
						want[i], _ = m["password"].(string)
						if want[i] == "" {
							if previous := previousSecretMatch(m, old, i, skipID); previous != nil {
								want[i], _ = previous["password"].(string)
							}
						}
					}
				}
				next := map[string]any{"users": children}
				mergeSecretMapAt(next, map[string]any{"users": old}, path)
				for i, item := range children {
					if m, ok := item.(map[string]any); ok && m["password"] != want[i] {
						t.Fatalf("identity mismatch at %d (%s)", i, path)
					}
				}
			}
		}
		old = append(old[1:], old[0])
	}
	previous := map[string]any{"users": []any{map[string]any{"id": "a", "password": "rotated"}}}
	next := map[string]any{"users": []any{map[string]any{"id": "a", "password": ""}}}
	mergeSecretMap(next, previous)
	if !reflect.DeepEqual(next, previous) {
		t.Fatal("stale lookup after source replacement")
	}
}

func BenchmarkNestedSecretMerge(b *testing.B) {
	for _, n := range []int{16, 2048} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			old, incoming := make([]any, n), make([]any, n)
			for i := range old {
				id := fmt.Sprint(i)
				old[i] = map[string]any{"id": id, "password": "fixture"}
				incoming[n-i-1] = map[string]any{"id": id, "password": ""}
			}
			previous, next := &config.Config{}, &config.Config{}
			previous.Channels = []config.Channel{{ID: "c", Config: map[string]any{"users": old}}}
			next.Channels = []config.Channel{{ID: "c", Config: map[string]any{"users": incoming}}}
			previous.VPNServers = []config.VPNServer{{ID: "s", Config: map[string]any{"users": old}}}
			next.VPNServers = []config.VPNServer{{ID: "s", Config: map[string]any{"users": incoming}}}
			b.ReportAllocs()
			for b.Loop() {
				for _, item := range incoming {
					item.(map[string]any)["password"] = ""
				}
				mergeRedactedSecrets(next, previous)
				for _, item := range incoming {
					if item.(map[string]any)["password"] != "fixture" {
						b.Fatal("lost credential")
					}
				}
			}
		})
	}
}
