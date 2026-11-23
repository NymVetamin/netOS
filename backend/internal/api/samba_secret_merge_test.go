package api

import (
	"context"
	"fmt"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestSambaSecretMergePreservesFirstMatch(t *testing.T) {
	previous := &config.Config{Samba: config.Samba{Users: []config.SambaUser{
		{ID: "a", Password: ""}, {ID: "a", Password: "second"}, {ID: "b", Password: "first"}, {ID: "b", Password: "last"}, {ID: "", Password: "empty-id"},
	}}}
	for range len(previous.Samba.Users) {
		for range 2 {
			incoming := []config.SambaUser{{ID: "b", Name: "renamed"}, {ID: "a"}, {ID: ""}, {ID: "unknown"}, {ID: "b", Password: "explicit"}}
			want := append([]config.SambaUser(nil), incoming...)
			for i := range want {
				if want[i].Password != "" {
					continue
				}
				for _, old := range previous.Samba.Users {
					if old.ID == want[i].ID {
						want[i].Password = old.Password
						break
					}
				}
			}
			next := &config.Config{Samba: config.Samba{Users: incoming}}
			mergeRedactedSecrets(next, previous)
			if !reflect.DeepEqual(next.Samba.Users, want) {
				t.Fatal("first-match merge changed")
			}
			mergeRedactedSecrets(next, previous)
			if !reflect.DeepEqual(next.Samba.Users, want) {
				t.Fatal("repeat changed merged credentials")
			}
		}
		previous.Samba.Users = append(previous.Samba.Users[1:], previous.Samba.Users[0])
	}
	next := &config.Config{Samba: config.Samba{Users: []config.SambaUser{{ID: "b"}}}}
	mergeRedactedSecrets(next, nil)
	if next.Samba.Users[0].Password != "" {
		t.Fatal("nil source restored credentials")
	}
	previous.Samba.Users = []config.SambaUser{{ID: "b", Password: "rotated"}}
	mergeRedactedSecrets(next, previous)
	if next.Samba.Users[0].Password != "rotated" {
		t.Fatal("stale credentials")
	}
}

func BenchmarkSambaSecretMerge(b *testing.B) {
	for _, n := range []int{16, 2048} {
		for _, scoped := range []bool{false, true} {
			b.Run(fmt.Sprintf("%d/scoped=%t", n, scoped), func(b *testing.B) {
				previous, next := config.Default(), config.Default()
				for i := 0; i < n; i++ {
					id := fmt.Sprintf("user%d", i)
					previous.Samba.Users = append(previous.Samba.Users, config.SambaUser{ID: id, Name: id, Password: "benchmark-fixture"})
					next.Samba.Users = append(next.Samba.Users, config.SambaUser{ID: id, Name: id})
				}
				r := httptest.NewRequest("PUT", "/api/config", nil)
				r = r.WithContext(context.WithValue(r.Context(), ctxRole, "admin"))
				b.ReportAllocs()
				for b.Loop() {
					out := next
					if scoped {
						var err error
						out, err = mergeScopedConfig(r, previous, next)
						if err != nil {
							b.Fatal(err)
						}
					} else {
						for i := range next.Samba.Users {
							next.Samba.Users[i].Password = ""
						}
						mergeRedactedSecrets(next, previous)
					}
					for _, user := range out.Samba.Users {
						if user.Password != "benchmark-fixture" {
							b.Fatal("lost credential")
						}
					}
				}
			})
		}
	}
}
