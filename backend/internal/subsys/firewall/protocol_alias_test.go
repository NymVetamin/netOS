package firewall

import "testing"

func TestIGMPNumericProtocolEquivalent(t *testing.T) {
	for _, suffix := range []string{" -j ACCEPT", " -j DROP"} {
		if canonicalRuleTokens("-A INPUT -p igmp"+suffix) != canonicalRuleTokens("-A INPUT -p 2"+suffix) {
			t.Fatal("iptables-save numeric IGMP differs from generated rule")
		}
	}
	if canonicalRuleTokens("-A INPUT -p 2 -j ACCEPT") == canonicalRuleTokens("-A INPUT -p 6 -j ACCEPT") {
		t.Fatal("distinct protocols compare equal")
	}
}
