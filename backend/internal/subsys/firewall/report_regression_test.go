package firewall

import (
	"github.com/netos-router/netos/internal/config"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestReportLogPrefixFitsKernelBuffer(t *testing.T) {
	for _, name := range []string{"Codex permit forwarded HTTP", "Длинное название правила для журнала"} {
		var b builder
		b.emitRule("FORWARD", config.FirewallRule{Name: name, Log: true, Action: "accept"}, "")
		tokens := splitRuleTokens(strings.Split(b.String(), "\n")[0])
		for i, token := range tokens {
			if token == "--log-prefix" {
				prefix, err := strconv.Unquote(tokens[i+1])
				if err != nil || len(prefix) > 28 || !utf8.ValidString(prefix) {
					t.Fatalf("invalid LOG prefix: %q", prefix)
				}
			}
		}
	}
}

func TestReportCommentQuotes(t *testing.T) {
	a := `-A FORWARD -m comment --comment "Codex" -j ACCEPT`
	b := `-A FORWARD -m comment --comment Codex -j ACCEPT`
	if canonicalRule(a) != canonicalRule(b) {
		t.Fatal("equivalent comments rejected")
	}
	if canonicalRule(a) == canonicalRule(strings.ReplaceAll(b, "Codex", "Other")) {
		t.Fatal("different comment ignored")
	}
}

func TestReportReplyNeverReceivesPolicyMark(t *testing.T) {
	cfg := config.Default()
	cfg.MultiWAN.Enabled, cfg.MultiWAN.Mode = true, "balance"
	cfg.WANs = []config.WAN{{ID: "a", Enabled: true, Weight: 1}, {ID: "b", Enabled: true, Weight: 1}}
	cfg.Channels = append(cfg.Channels, config.Channel{ID: "wg", Index: 1, Enabled: true, Type: "wireguard"})
	cfg.Policies = []config.Policy{{ID: "p", Enabled: true, Channel: "wg"}}
	for _, sticky := range []bool{false, true} {
		cfg.MultiWAN.StickyConnections = sticky
		rules, _ := Build(cfg)
		for _, line := range strings.Split(rules.IPv4, "\n") {
			if strings.HasPrefix(line, "-A PREROUTING ") && (strings.Contains(line, "CONNMARK") || strings.Contains(line, "NETOS-POLICY") || strings.Contains(line, "NETOS-MULTIWAN")) && !strings.Contains(line, "--ctdir ORIGINAL") {
				t.Errorf("reply can be marked: %s", line)
			}
		}
	}
}
