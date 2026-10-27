package api

import (
	"github.com/netos-router/netos/internal/config"
	"reflect"
	"testing"
)

func TestPlanResolverArrayIdentityAndPosition(t *testing.T) {
	first := map[string]any{"id": "same", "name": "first"}
	second := map[string]any{"id": "same", "name": "second"}
	blank := map[string]any{"id": "", "name": "blank"}
	list := []any{first, second, blank, map[string]any{"id": 7}, nil}
	var resolver planResolver
	for _, tc := range []struct {
		key, id string
		want    any
	}{
		{"id", "same", first}, {"id", "", blank}, {"id", "7", nil}, {"id", "missing", nil},
		{"name", "second", second}, {"", "0", first}, {"", "1", second}, {"", "-1", nil}, {"", "5", nil},
	} {
		if got := resolver.arrayItem(list, tc.key, tc.id); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s/%s: got %v", tc.key, tc.id, got)
		}
	}
	if got := resolver.arrayItem(list[:1], "id", ""); got != nil {
		t.Fatal("different slice length reused index")
	}
	other := []any{map[string]any{"id": "same", "name": "after"}}
	if got := resolver.arrayItem(other, "id", "same"); !reflect.DeepEqual(got, other[0]) {
		t.Fatal("before and after shared an index")
	}
}

func TestPlanResolverDoesNotRetainNamesAcrossPlans(t *testing.T) {
	a := config.Default()
	a.Clients = []config.Client{{ID: "one", Name: "Before"}}
	b := *a
	b.Clients = []config.Client{{ID: "one", Name: "After"}}
	first := configurationChanges(a, &b)
	if len(first) != 1 || first[0].Before != "Before" || first[0].After != "After" {
		t.Fatalf("unexpected changes: %#v", first)
	}
	b.Clients[0].Name = "Changed again"
	second := configurationChanges(a, &b)
	if len(second) != 1 || second[0].After != "Changed again" {
		t.Fatalf("stale result: %#v", second)
	}
	b.Clients[0].Name = "Before"
	if changes := configurationChanges(a, &b); len(changes) != 0 {
		t.Fatalf("reverted name still differs: %#v", changes)
	}
}
