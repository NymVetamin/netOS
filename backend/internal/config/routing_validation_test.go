package config

import "testing"

func validRoutingConfig() *Config {
	cfg := Default()
	cfg.Routing.Tables = []RouteTable{{ID: "qa-table", Name: "qa-table", Number: 200}}
	cfg.Routing.Static = []StaticRoute{{
		ID: "qa-route", Name: "QA route", Enabled: true,
		Destination: "192.0.2.0/24", Interface: "eth0", Type: "unicast",
		Metric: 10, Table: "qa-table",
	}}
	cfg.Routing.Rules = []RouteRule{{
		ID: "qa-rule", Name: "QA rule", Enabled: true, Priority: 20100,
		From: "198.51.100.0/24", FwMark: "0x10/0xff", Interface: "eth0", Table: "qa-table",
	}}
	return cfg
}

func TestRoutingValidationAcceptsSupportedRouteTypesAndMarks(t *testing.T) {
	for _, routeType := range []string{"", "unicast", "blackhole", "unreachable", "prohibit"} {
		cfg := validRoutingConfig()
		cfg.Routing.Static[0].Type = routeType
		if routeType != "" && routeType != "unicast" {
			cfg.Routing.Static[0].Interface = ""
		}
		if problem(t, cfg, "routing.static[0].type", "тип") {
			t.Fatalf("supported route type %q rejected", routeType)
		}
	}
	for _, mark := range []string{"1", "4294967295", "0x10", "0x10/0xff"} {
		cfg := validRoutingConfig()
		cfg.Routing.Rules[0].FwMark = mark
		if problem(t, cfg, "routing.rules[0].fwmark", "метка") {
			t.Fatalf("supported fwmark %q rejected", mark)
		}
	}
}

func TestRoutingValidationRejectsValuesThatWouldFailOrChangeMeaning(t *testing.T) {
	tests := []struct {
		path   string
		mutate func(*Config)
	}{
		{"routing.static[0].type", func(c *Config) { c.Routing.Static[0].Type = "throw" }},
		{"routing.static[0].interface", func(c *Config) { c.Routing.Static[0].Interface = "bad name" }},
		{"routing.static[0].metric", func(c *Config) { c.Routing.Static[0].Metric = -1 }},
		{"routing.static[0].gateway", func(c *Config) { c.Routing.Static[0].Gateway = "2001:db8::1" }},
		{"routing.rules[0].fwmark", func(c *Config) { c.Routing.Rules[0].FwMark = "0x100000000" }},
		{"routing.rules[0].fwmark", func(c *Config) { c.Routing.Rules[0].FwMark = "1/2/3" }},
		{"routing.rules[0].interface", func(c *Config) { c.Routing.Rules[0].Interface = "bad/name" }},
	}
	for _, tc := range tests {
		cfg := validRoutingConfig()
		tc.mutate(cfg)
		if !problem(t, cfg, tc.path, "") {
			t.Fatalf("invalid value accepted at %s", tc.path)
		}
	}
}

func TestRoutingValidationAcceptsMatchingIPv6Route(t *testing.T) {
	cfg := validRoutingConfig()
	cfg.Routing.Static[0].Destination = "2001:db8:1::/64"
	cfg.Routing.Static[0].Gateway = "2001:db8::1"
	cfg.Routing.Static[0].Interface = ""
	if problem(t, cfg, "routing.static[0].gateway", "семейство") {
		t.Fatal("matching IPv6 destination and gateway rejected")
	}
}
