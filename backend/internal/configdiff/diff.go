// Package configdiff compares JSON-shaped values. It knows nothing about
// router settings, permissions, secrets, display labels or execution plans.
package configdiff

import (
	"reflect"
	"slices"
	"sort"
	"strconv"
)

type Value struct {
	Present bool
	Data    any
}

type Change struct {
	Path          []string
	Kind          string
	Before, After Value
}

// Identity returns an array item's stable key, or an empty string for an
// ordered array without identities. The caller supplies its schema knowledge.
func Diff(before, after any, identity func([]string) string) []Change {
	changes := []Change{}
	if _, object := before.(map[string]any); object && reflect.DeepEqual(before, after) {
		return changes
	}
	add := func(path []string, kind string, a, b Value) {
		changes = append(changes, Change{slices.Clone(path), kind, a, b})
	}
	var walk func(Value, Value, []string)
	walk = func(a, b Value, path []string) {
		am, aMap := a.Data.(map[string]any)
		bm, bMap := b.Data.(map[string]any)
		if (aMap || bMap) && (a.Data == nil || aMap) && (b.Data == nil || bMap) {
			if len(am) == 0 && len(bm) == 0 {
				if a.Present != b.Present || !reflect.DeepEqual(a.Data, b.Data) {
					add(path, "change", a, b)
				}
				return
			}
			ordered := make([]string, 0, max(len(am), len(bm)))
			for k := range am {
				ordered = append(ordered, k)
			}
			for k := range bm {
				if _, exists := am[k]; !exists {
					ordered = append(ordered, k)
				}
			}
			sort.Strings(ordered)
			for _, k := range ordered {
				av, ap := am[k]
				bv, bp := bm[k]
				walk(Value{ap, av}, Value{bp, bv}, append(path, k))
			}
			return
		}
		if a.Present == b.Present && reflect.DeepEqual(a.Data, b.Data) {
			return
		}
		aa, aList := a.Data.([]any)
		ba, bList := b.Data.([]any)
		if (aList || bList) && (a.Data == nil || aList) && (b.Data == nil || bList) {
			if len(aa) == 0 && len(ba) == 0 {
				add(path, "change", a, b)
				return
			}
			key := ""
			if identity != nil {
				path = slices.Clone(path)
				key = identity(path)
			}
			ai, ax, ak := index(aa, key)
			bi, bx, bk := index(ba, key)
			if key != "" && ak && bk {
				order := append([]string{}, bi...)
				for _, id := range ai {
					if _, ok := bx[id]; !ok {
						order = append(order, id)
					}
				}
				if len(ai) > 0 && len(bi) > 0 && !reflect.DeepEqual(ai, bi) {
					asValues := func(ids []string) []any {
						values := []any{}
						for _, id := range ids {
							values = append(values, id)
						}
						return values
					}
					add(path, "reorder", Value{true, asValues(ai)}, Value{true, asValues(bi)})
				}
				for _, id := range order {
					av, ap := ax[id]
					bv, bp := bx[id]
					p := append(path, id)
					if !ap {
						add(p, "add", Value{}, Value{true, bv})
					}
					if !bp {
						add(p, "remove", Value{true, av}, Value{})
					}
					walk(Value{ap, av}, Value{bp, bv}, p)
				}
				return
			}
			objects := false
			for _, xs := range [][]any{aa, ba} {
				for _, x := range xs {
					if _, ok := x.(map[string]any); ok {
						objects = true
					}
				}
			}
			if objects {
				for i := 0; i < max(len(aa), len(ba)); i++ {
					av, bv := Value{}, Value{}
					if i < len(aa) {
						av = Value{true, aa[i]}
					}
					if i < len(ba) {
						bv = Value{true, ba[i]}
					}
					walk(av, bv, append(path, strconv.Itoa(i)))
				}
				return
			}
		}
		add(path, "change", a, b)
	}
	walk(Value{true, before}, Value{true, after}, nil)
	return changes
}

func index(items []any, key string) ([]string, map[string]any, bool) {
	order := []string{}
	values := map[string]any{}
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, nil, false
		}
		id, ok := m[key].(string)
		if !ok || id == "" {
			return nil, nil, false
		}
		if _, duplicate := values[id]; duplicate {
			return nil, nil, false
		}
		order = append(order, id)
		values[id] = item
	}
	return order, values, true
}
