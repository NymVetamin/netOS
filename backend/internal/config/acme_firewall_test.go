package config

import "testing"

func TestNormalizeKeepsACMEChallengeReachableOnlyInACMEMode(t *testing.T) {
	cfg := Default()
	cfg.System.Panel.TLS = TLS{Mode: "acme", Domain: "router.example.net", AcceptTOS: true}
	cfg.Normalize()

	var found bool
	for _, rule := range cfg.Firewall.Rules {
		if rule.ID != "sys-acme" {
			continue
		}
		found = true
		if !rule.System || !rule.Enabled || rule.Zone != "global" || rule.Flow != "in" ||
			rule.Action != "accept" || rule.Protocol != "tcp" || rule.DstPort != "80" {
			t.Fatalf("ACME firewall rule is not usable: %#v", rule)
		}
	}
	if !found {
		t.Fatal("ACME mode did not add the HTTP-01 firewall rule")
	}

	cfg.System.Panel.TLS = TLS{Mode: "selfsigned"}
	cfg.Normalize()
	for _, rule := range cfg.Firewall.Rules {
		if rule.ID == "sys-acme" {
			t.Fatalf("self-signed mode retained ACME firewall rule: %#v", rule)
		}
	}
}
