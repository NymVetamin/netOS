package config

import "testing"

func TestNormalizeAssignsStableUniqueWANIndexes(t *testing.T) {
	cfg := Default()
	cfg.WANs = []WAN{
		{ID: "first", Index: 2},
		{ID: "second"},
		{ID: "third"},
	}

	cfg.Normalize()
	if cfg.WANs[0].Index != 2 || cfg.WANs[1].Index != 1 || cfg.WANs[2].Index != 3 {
		t.Fatalf("unexpected indexes: %d, %d, %d", cfg.WANs[0].Index, cfg.WANs[1].Index, cfg.WANs[2].Index)
	}
	cfg.Normalize()
	if cfg.WANs[0].Index != 2 || cfg.WANs[1].Index != 1 || cfg.WANs[2].Index != 3 {
		t.Fatalf("indexes changed after a second normalization: %d, %d, %d", cfg.WANs[0].Index, cfg.WANs[1].Index, cfg.WANs[2].Index)
	}
}

func TestBalanceRequiresPositiveWeightsAndUniqueIndexes(t *testing.T) {
	cfg := Default()
	cfg.MultiWAN.Enabled = true
	cfg.MultiWAN.Mode = "balance"
	cfg.Interfaces = []Interface{{ID: "if0", Name: "wan0"}, {ID: "if1", Name: "wan1"}}
	cfg.WANs = []WAN{
		{ID: "first", Index: 1, Name: "First", Interface: "if0", Enabled: true, Proto: "dhcp", Metric: 100, Weight: 1},
		{ID: "second", Index: 1, Name: "Second", Interface: "if1", Enabled: true, Proto: "dhcp", Metric: 200, Weight: 0},
	}

	if !problem(t, cfg, "wans[1].index", "already") && !problem(t, cfg, "wans[1].index", "занят") {
		t.Fatal("duplicate WAN index accepted")
	}
	if !problem(t, cfg, "wans[1].weight", "положительным") {
		t.Fatal("zero balance weight accepted")
	}
}
