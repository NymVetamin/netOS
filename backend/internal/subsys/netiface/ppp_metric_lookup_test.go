package netiface

import (
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func previousPPPMetricChanges(wans []config.WAN, routes []pppDefaultRoute) map[string]bool {
	out := map[string]bool{}
	for _, w := range wans {
		if w.Proto != "pppoe" && w.Proto != "l2tp" {
			continue
		}
		for _, route := range routes {
			if route.Interface == PPPoEInterface(w.ID) && route.Metric != w.Metric {
				out[w.ID] = true
			}
		}
	}
	return out
}

func BenchmarkPPPMetricLedgerLookup(b *testing.B) {
	for _, n := range []int{16, 2048} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s := NewWAN(nil)
			s.OwnedRoutePath = filepath.Join(b.TempDir(), "owned.json")
			var routes []pppDefaultRoute
			var wans []config.WAN
			for i := 0; i < n; i++ {
				id := fmt.Sprint(i)
				wans = append(wans, config.WAN{ID: id, Proto: "pppoe", Metric: i + 1})
				routes = append(routes, pppDefaultRoute{Interface: PPPoEInterface(id), Metric: i})
			}
			if err := s.writePPPDefaultRoutes(routes); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				owned, err := s.readPPPDefaultRoutes()
				if err != nil {
					b.Fatal(err)
				}
				got := changedPPPMetrics(wans, owned)
				if len(got) != n {
					b.Fatal("lost changed metrics")
				}
			}
		})
	}
}

func TestPPPMetricLookupEquivalence(t *testing.T) {
	wans := []config.WAN{{ID: "a", Proto: "pppoe", Metric: 100}, {ID: "a", Proto: "l2tp", Metric: 200}, {ID: "b", Proto: "pppoe", Metric: 100}, {ID: "c", Proto: "static", Metric: 99}, {ID: "absent", Proto: "l2tp", Metric: 10}, {ID: "", Proto: "pppoe"}}
	routes := []pppDefaultRoute{{"ppp-a", 100}, {"ppp-a", 100}, {"ppp-a", 200}, {"ppp-b", 100}, {"ppp-c", 20}, {"ppp-", 0}, {"foreign", 12}}
	for range len(routes) {
		for range 2 {
			got := changedPPPMetrics(wans, routes)
			if want := previousPPPMetricChanges(wans, routes); !reflect.DeepEqual(got, want) {
				t.Fatal("metric classification differs")
			}
		}
		routes = append(routes[1:], routes[0])
	}
	for _, next := range [][]pppDefaultRoute{nil, {{"ppp-a", 100}}, {{"ppp-b", 200}}, {{"ppp-b", 100}}} {
		if got, want := changedPPPMetrics(wans, next), previousPPPMetricChanges(wans, next); !reflect.DeepEqual(got, want) {
			t.Fatal("new route snapshot changed classification")
		}
	}
	if len(changedPPPMetrics(nil, routes)) != 0 {
		t.Fatal("empty WAN list changed")
	}
}
