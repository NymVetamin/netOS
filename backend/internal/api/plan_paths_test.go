package api

import (
	"fmt"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestPlanEscapesPathSegmentsAndRefreshes(t *testing.T) {
	a, b := config.Default(), config.Default()
	for _, id := range []string{"a/b", "~1", "Сеть/~"} {
		a.Firewall.Rules = []config.FirewallRule{{ID: id}}
		b.Firewall.Rules = []config.FirewallRule{{ID: id, Enabled: true}}
		wantID := map[string]string{"a/b": "a~1b", "~1": "~01", "Сеть/~": "Сеть~1~0"}[id]
		for range 2 {
			changes := configurationChanges(a, b)
			if len(changes) != 1 || changes[0].Path != "/firewall/rules/"+wantID+"/enabled" {
				t.Fatal(changes)
			}
			if again := configurationChanges(a, b); !reflect.DeepEqual(changes, again) {
				t.Fatal("repeated plan differs")
			}
			a, b = b, a
		}
		b.Firewall.Rules[0].Enabled = false
		if changes := configurationChanges(a, b); len(changes) != 0 {
			t.Fatal("plan retained a previous change", changes)
		}
	}
}

func BenchmarkDescribePlanRuleChanges(b *testing.B) {
	for _, n := range []int{10, 1000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			old, next := config.Default(), config.Default()
			for i := 0; i < n; i++ {
				rule := config.FirewallRule{ID: fmt.Sprintf("r%d", i), Zone: "global", Flow: "in", Action: "accept"}
				old.Firewall.Rules = append(old.Firewall.Rules, rule)
				rule.Enabled = true
				next.Firewall.Rules = append(next.Firewall.Rules, rule)
			}
			r := httptest.NewRequest("POST", "/api/config/plan", nil)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				result, err := describePlan(r, old, next, nil, 1)
				if err != nil || len(result.Changes) != n {
					b.Fatal(err, len(result.Changes))
				}
			}
		})
	}
}
