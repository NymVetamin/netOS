package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestMultiWANBalanceMarksAndPersistsConnections(t *testing.T) {
	cfg := config.Default()
	cfg.MultiWAN.Enabled = true
	cfg.MultiWAN.Mode = "balance"
	cfg.Interfaces = []config.Interface{{ID: "a", Name: "wan0"}, {ID: "b", Name: "wan1"}}
	cfg.WANs = []config.WAN{{ID: "a", Index: 1, Name: "A", Interface: "a", Enabled: true, Proto: "static", Weight: 1}, {ID: "b", Index: 2, Name: "B", Interface: "b", Enabled: true, Proto: "static", Weight: 3}}
	rules, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"NETOS-MULTIWAN", "--probability 0.250000", "--set-mark 0x3001", "--set-mark 0x3002", "CONNMARK --save-mark", "POSTROUTING -o wan0", "POSTROUTING -o wan1"} {
		if !strings.Contains(rules.IPv4, want) {
			t.Errorf("нет %q:\n%s", want, rules.IPv4)
		}
	}
}
