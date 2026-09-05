package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

// «Передать дальше по списку» обещает, что совпавший пакет проверяется
// следующей строкой. RETURN во встроенной цепочке делает обратное: завершает
// проверку и отдаёт пакет политике по умолчанию, поэтому следующее правило
// «Отбросить молча» не срабатывало вовсе и запрет обходился.
func TestContinueRuleFallsThroughToNextRule(t *testing.T) {
	cfg := config.Default()
	cfg.Firewall.Enabled = true
	cfg.Firewall.Rules = append(cfg.Firewall.Rules,
		config.FirewallRule{
			ID: "u1", Name: "r934 filter", Enabled: true, Zone: "global",
			Flow: "out", Action: "continue", Protocol: "tcp", DstPort: "8001",
		},
		config.FirewallRule{
			ID: "u2", Name: "r934 after-continue", Enabled: true, Zone: "global",
			Flow: "out", Action: "drop", Protocol: "tcp", DstPort: "8001",
		},
	)
	set, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var first, second string
	for _, line := range strings.Split(set.IPv4, "\n") {
		if strings.Contains(line, `--comment "r934 filter"`) {
			first = line
		}
		if strings.Contains(line, `--comment "r934 after-continue"`) {
			second = line
		}
	}
	if first == "" || second == "" {
		t.Fatalf("правила не попали в ruleset:\n%s", set.IPv4)
	}
	if strings.Contains(first, " -j ") {
		t.Fatalf("правило продолжения получило переход и обрывает проверку: %s", first)
	}
	if !strings.HasSuffix(second, "-j DROP") {
		t.Fatalf("следующее правило перестало запрещать: %s", second)
	}
}

// Правило без единого условия собрать не из чего: у iptables должен остаться
// хотя бы один match, и им становится комментарий с названием правила.
func TestContinueRuleWithoutConditionsKeepsAMatch(t *testing.T) {
	cfg := config.Default()
	cfg.Firewall.Enabled = true
	cfg.Firewall.Rules = append(cfg.Firewall.Rules, config.FirewallRule{
		ID: "u1", Name: "", Enabled: true, Zone: "global", Flow: "in", Action: "continue",
	})
	set, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(set.IPv4, "\n") {
		if line == "-A INPUT" {
			t.Fatalf("правило без условий и без перехода:\n%s", set.IPv4)
		}
	}
}
