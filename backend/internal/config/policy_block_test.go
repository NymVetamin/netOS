package config

import "testing"

func TestPolicyBlockValidation(t *testing.T) {
	c := Default()
	c.Policies = []Policy{{ID: "deny", Enabled: true, Channel: InternetBlockChannel, DstIP: "192.0.2.0/24"}}
	if r := c.Validate(); r.HasErrors() {
		t.Fatal(r.Problems)
	}
	c.IPv6.Mode = "passthrough"
	if !hasErrorAt(c.Validate(), "policies[0].channel") {
		t.Fatal("IPv6 bypass accepted")
	}
	c.Policies[0].Enabled = false
	if hasErrorAt(c.Validate(), "policies[0].channel") {
		t.Fatal("disabled block rejected")
	}
	c.Policies[0].Channel = "missing"
	if !hasErrorAt(c.Validate(), "policies[0].channel") {
		t.Fatal("unknown channel accepted")
	}
}
