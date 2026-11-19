package config

import "testing"

func TestL2TPUnderlayFollowsAllDataUplinks(t *testing.T) {
	c := Default()
	c.MultiWAN.Enabled = true
	c.WANs = []WAN{{ID: "primary", Enabled: true, Proto: "l2tp", Metric: 100}, {ID: "backup", Enabled: true, Metric: 200}, {ID: "management", Enabled: true, Metric: 900}}
	metric := func(w WAN) int {
		t.Helper()
		result, err := w.L2TPUnderlayMetric(c.L2TPMetricBase())
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if got := metric(c.WANs[0]); got <= 900 {
		t.Fatalf("underlay metric %d can steal backup traffic", got)
	}
	c.WANs = append(c.WANs, WAN{ID: "second-tunnel", Enabled: true, Proto: "l2tp", Metric: 300}, WAN{ID: "disabled", Metric: 9000})
	if metric(c.WANs[0]) != 1010 || metric(c.WANs[3]) != 1210 {
		t.Fatal("underlays collide or a disabled WAN changes priority")
	}
	c.WANs[2].Metric = 1500
	if metric(c.WANs[0]) <= 1500 {
		t.Fatal("changed backup priority overtakes the underlay")
	}
	c.MultiWAN.Enabled = false
	if got := metric(c.WANs[0]); got != 110 {
		t.Fatalf("single WAN behavior changed: %d", got)
	}
}

func TestL2TPMetricValidationBounds(t *testing.T) {
	c := Default()
	c.Interfaces = []Interface{{ID: "uplink", Name: "eth0", Type: "physical", Enabled: true}, {ID: "backup", Name: "eth1", Type: "physical", Enabled: true}}
	c.Components = append(c.Components, Component{ID: "l2tp", Installed: true})
	c.WANs = []WAN{{ID: "isp", Index: 1, Enabled: true, Proto: "l2tp", Interface: "uplink", Server: "192.0.2.1", Username: "u"}, {ID: "other", Index: 2, Enabled: true, Proto: "dhcp", Interface: "backup"}}
	for _, tc := range []struct {
		metric, other  int
		multi, invalid bool
	}{
		{100, 200, false, false}, {1<<63 - 1, 200, false, true}, {0, 200, false, true},
		{100, 1<<32 - 1 - 110, true, false}, {100, 1<<32 - 110, true, true},
		{100, 1<<63 - 1, true, true}, {100, 200, true, false},
	} {
		c.WANs[0].Metric, c.WANs[1].Metric, c.MultiWAN.Enabled = tc.metric, tc.other, tc.multi
		r := c.Validate()
		p, found := problemAt(r, "wans[0].metric")
		if r.HasErrors() != tc.invalid || found != tc.invalid || (found && p.Severity != "error") {
			t.Fatalf("%+v: %v", tc, r.Problems)
		}
	}
}
