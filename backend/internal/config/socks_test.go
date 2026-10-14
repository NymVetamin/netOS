package config

import "testing"

func socksFixture() *Config {
	c := Default()
	c.Components = append(c.Components, Component{ID: "xray", Installed: true})
	c.Networks = []Network{{ID: "lan", Enabled: true}}
	c.Socks = Socks{Enabled: true, Port: 1080, Networks: []string{"lan"}, Auth: true, Username: "test", Password: "test-password", Channel: "direct"}
	return c
}
func TestSocksValidation(t *testing.T) {
	c := socksFixture()
	r := &ValidationResult{}
	c.validateSocks(r)
	if r.HasErrors() {
		t.Fatal(r.Problems)
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.Socks.AllowWAN = true; c.Socks.Auth = false },
		func(c *Config) { c.Firewall.Enabled = false },
		func(c *Config) { c.Socks.Channel = "missing" },
		func(c *Config) { c.Socks.Password = "short" },
		func(c *Config) { c.Socks.Networks = []string{"missing"} },
		func(c *Config) { c.Socks.Networks = nil },
		func(c *Config) { c.Components = nil },
	} {
		c := socksFixture()
		change(c)
		r := &ValidationResult{}
		c.validateSocks(r)
		if !r.HasErrors() {
			t.Fatalf("invalid config accepted: %+v", c.Socks)
		}
	}
}
