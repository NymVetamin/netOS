package config

import "testing"

func TestL2TPUnderlayFollowsAllDataUplinks(t *testing.T) {
	c := Default()
	c.MultiWAN.Enabled = true
	c.WANs = []WAN{{ID: "primary", Enabled: true, Proto: "l2tp", Metric: 100}, {ID: "backup", Enabled: true, Metric: 200}, {ID: "management", Enabled: true, Metric: 900}}
	if got := c.L2TPUnderlayMetric(c.WANs[0]); got <= 900 {
		t.Fatalf("underlay metric %d can steal backup traffic", got)
	}
	c.WANs = append(c.WANs, WAN{ID: "second-tunnel", Enabled: true, Proto: "l2tp", Metric: 300}, WAN{ID: "disabled", Metric: 9000})
	if c.L2TPUnderlayMetric(c.WANs[0]) != 1010 || c.L2TPUnderlayMetric(c.WANs[3]) != 1210 {
		t.Fatal("underlays collide or a disabled WAN changes priority")
	}
	c.WANs[2].Metric = 1500
	if c.L2TPUnderlayMetric(c.WANs[0]) <= 1500 {
		t.Fatal("changed backup priority overtakes the underlay")
	}
	c.MultiWAN.Enabled = false
	if got := c.L2TPUnderlayMetric(c.WANs[0]); got != 110 {
		t.Fatalf("single WAN behavior changed: %d", got)
	}
}
