package config

import "testing"

func TestL2TPChannelIPsecValidation(t *testing.T) {
	c := Default()
	ch := Channel{Type: "l2tp", Enabled: true, Mode: "tun", Config: map[string]any{"server": "vpn.example", "username": "alice", "password": "password", "ipsec": true}}
	validate := func() ValidationResult { r := ValidationResult{}; c.validateL2TPChannel(&r, "channel", ch); return r }
	if r := validate(); !hasErrorAt(&r, "channel.config.preshared_key") || !hasErrorAt(&r, "channel.enabled") {
		t.Fatal(r)
	}
	c.Components = append(c.Components, Component{ID: "strongswan", Installed: true})
	ch.Config["preshared_key"] = "provided-key"
	if r := validate(); r.HasErrors() {
		t.Fatal(r)
	}
	ch.Config["preshared_key"] = "bad\nkey"
	if r := validate(); !hasErrorAt(&r, "channel.config.preshared_key") {
		t.Fatal(r)
	}
	ch.Config["ipsec"] = false
	delete(ch.Config, "preshared_key")
	if r := validate(); r.HasErrors() {
		t.Fatal(r)
	}
}
