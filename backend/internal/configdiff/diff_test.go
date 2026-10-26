package configdiff

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestIdentityAndOrdering(t *testing.T) {
	a := []any{map[string]any{"id": "a", "value": 1}, map[string]any{"id": "b", "value": 2}}
	b := []any{map[string]any{"id": "b", "value": 3}, map[string]any{"id": "a", "value": 1}}
	diff := Diff(a, b, func([]string) string { return "id" })
	if len(diff) != 2 || diff[0].Kind != "reorder" || !reflect.DeepEqual(diff[1].Path, []string{"b", "value"}) || diff[1].Before.Data != 2 || diff[1].After.Data != 3 {
		t.Fatal(diff)
	}
	if a[1].(map[string]any)["value"] != 2 {
		t.Fatal("mutated input")
	}
}

func TestAdditionRemovalAndMissingNull(t *testing.T) {
	for _, v := range []any{nil, map[string]any{}, []any{}, []any{nil}, false, "", 0} {
		a, b := map[string]any{}, map[string]any{"x": v}
		changes := Diff(a, b, nil)
		if len(changes) != 1 || changes[0].Before.Present || !changes[0].After.Present || !reflect.DeepEqual(changes[0].After.Data, v) {
			t.Fatalf("%#v: %+v", v, changes)
		}
		back := Diff(b, a, nil)
		if len(back) != 1 || !back[0].Before.Present || back[0].After.Present {
			t.Fatal(back)
		}
	}
	a := []any{map[string]any{"id": "a", "on": true}}
	b := []any{map[string]any{"id": "b", "on": true}}
	kinds := map[string]int{}
	for _, c := range Diff(a, b, func([]string) string { return "id" }) {
		kinds[c.Kind]++
	}
	if kinds["add"] != 1 || kinds["remove"] != 1 || kinds["reorder"] != 1 {
		t.Fatal(kinds)
	}
}

func FuzzDiffEqualAndReadOnly(f *testing.F) {
	for _, seed := range []string{`{"x":null}`, `{"x":[]}`, `[{"id":"a"}]`, `{"opaque":{"users":[{"id":"credential"}]}}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		var value any
		if json.Unmarshal([]byte(text), &value) != nil {
			return
		}
		before, _ := json.Marshal(value)
		if got := Diff(value, value, nil); len(got) != 0 {
			t.Fatal(got)
		}
		Diff(value, map[string]any{}, nil)
		after, _ := json.Marshal(value)
		if string(before) != string(after) {
			t.Fatal("input mutated")
		}
	})
}
