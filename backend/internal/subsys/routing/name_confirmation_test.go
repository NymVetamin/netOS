package routing

import (
	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"testing"
)

func TestRoutingNamesConfirmation(t *testing.T) {
	for _, mode := range []string{"names", "missing route", "missing rule", "metric", "priority"} {
		t.Run(mode, func(t *testing.T) {
			old := config.Default()
			old.Routing.Static = []config.StaticRoute{{Enabled: true, Name: "old route", Destination: "192.0.2.0/24", Type: "blackhole", Table: "200"}}
			old.Routing.Rules = []config.RouteRule{{Enabled: true, Name: "old rule", Priority: 20100, From: "198.51.100.0/24", Table: "200"}}
			next := *old
			next.Routing.Static = append([]config.StaticRoute(nil), old.Routing.Static...)
			next.Routing.Rules = append([]config.RouteRule(nil), old.Routing.Rules...)
			next.Routing.Static[0].Name = "new route"
			next.Routing.Rules[0].Name = "new rule"
			responses := map[string]runnerResponse{
				"ip -4 route show table all proto static": {out: "blackhole 192.0.2.0/24 table 200"},
				"ip -4 rule show":                         {out: "20100: from 198.51.100.0/24 lookup 200"},
			}
			switch mode {
			case "missing route":
				delete(responses, "ip -4 route show table all proto static")
			case "missing rule":
				delete(responses, "ip -4 rule show")
			case "metric":
				next.Routing.Static[0].Metric++
			case "priority":
				next.Routing.Rules[0].Priority++
			}
			actions, err := New(&recordingRunner{responses: responses}).Plan(old, &next)
			if err != nil || len(actions) != 2 {
				t.Fatalf("plan: %v %v", actions, err)
			}
			for i := range actions {
				actions[i].Subsystem = "routing"
			}
			if !apply.NeedsConfirmation(actions) != (mode == "names") {
				t.Fatalf("classification: %v", actions)
			}
			if old.Routing.Static[0].Name != "old route" || next.Routing.Rules[0].Name != "new rule" {
				t.Fatal("comparison mutated inputs")
			}
		})
	}
}
