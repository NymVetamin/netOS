package firewall

import (
	"context"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestDynamicClassifierStillDetectsForeignChanges(t *testing.T) {
	cfg := config.Default()
	cfg.MultiWAN = config.MultiWAN{Enabled: true, Mode: "balance", StickyConnections: true}
	cfg.WANs = []config.WAN{{ID: "one", Index: 1, Enabled: true, Weight: 1}, {ID: "two", Index: 2, Enabled: true, Weight: 1}}
	rs, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dynamic := "-A NETOS-MULTIWAN -m addrtype --dst-type LOCAL -j RETURN\n-A NETOS-MULTIWAN -j MARK --set-mark 0x3002\n-A NETOS-MULTIWAN -j CONNMARK --save-mark"
	s := New(nil, t.TempDir())
	s.MultiWANClassifier = func(*config.Config) string { return dynamic }
	s.runtimeRules(cfg, rs)
	r := cleanFirewallRunner(rs)
	s.Runner = r
	actions, err := s.Plan(cfg, cfg)
	if err != nil || len(actions) != 0 {
		t.Fatalf("healthy dynamic rules: %v %v", actions, err)
	}
	r.outputs["iptables-save"] = strings.Replace(rs.IPv4, "-A NETOS-MULTIWAN -j MARK --set-mark 0x3002", "-A NETOS-MULTIWAN -j ACCEPT", 1)
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("foreign rule in dynamic chain ignored")
	}
}
