package config

import "testing"

func TestStaticRouteRejectsEquivalentDestinations(t *testing.T) {
	for _, tc := range []struct {
		name, first, second, firstTable, secondTable, gateway string
	}{
		{"IPv4 host", "203.0.113.1", "203.0.113.1/32", "", "", ""},
		{"IPv6 host", "2001:db8::1", "2001:0db8:0:0:0:0:0:1/128", "", "", ""},
		{"main table", "203.0.113.0/24", "203.0.113.0/24", "", "main", ""},
		{"IPv4 default", "default", "0.0.0.0/0", "", "", ""},
		{"IPv6 default", "default", "::/0", "", "", "2001:db8::2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Routing.Static = []StaticRoute{
				{ID: "first", Name: "first", Enabled: true, Destination: tc.first, Table: tc.firstTable, Gateway: tc.gateway, Type: "blackhole"},
				{ID: "second", Name: "second", Enabled: true, Destination: tc.second, Table: tc.secondTable, Type: "prohibit"},
			}
			if !hasRemainingProblem(cfg, "routing.static[1].destination", "error") {
				t.Fatal("equivalent routes accepted although the second replaces the first in the kernel")
			}
			cfg.Routing.Static[1].Metric = 17
			if hasRemainingProblem(cfg, "routing.static[1].destination", "error") {
				t.Fatal("distinct metrics should coexist")
			}
			cfg.Routing.Static[1].Metric = 0
			cfg.Routing.Static[1].Enabled = false
			if hasRemainingProblem(cfg, "routing.static[1].destination", "error") {
				t.Fatal("disabled route should not conflict")
			}
		})
	}
}
