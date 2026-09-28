package config

import "testing"

func sambaFixture() *Config {
	c := Default()
	c.Components = append(c.Components, Component{ID: "samba", Installed: true})
	c.Interfaces = []Interface{{ID: "eth1", Name: "eth1", Type: "physical", Enabled: true}}
	c.Networks = []Network{{ID: "lan", Name: "LAN", Interface: "eth1", RouterAddress: "192.168.5.1/24", Enabled: true, Zone: "lan"}}
	c.Samba = Samba{Enabled: true, Networks: []string{"lan"}, Volumes: []StorageVolume{{ID: "disk", UUID: "ABCD-1234", Filesystem: "vfat", Enabled: true}}, Users: []SambaUser{{ID: "u", Name: "alice", Password: "Password123"}}, Shares: []SambaShare{{ID: "s", Name: "USB", Enabled: true, Volume: "disk", Users: []string{"u"}, ReadOnly: true}}}
	return c
}
func TestSambaValidation(t *testing.T) {
	base := sambaFixture()
	r := &ValidationResult{}
	base.validateSamba(r)
	if r.HasErrors() {
		t.Fatal(r.Problems)
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"missing component", func(c *Config) { c.Components = nil }},
		{"no networks", func(c *Config) { c.Samba.Networks = nil }},
		{"isolated", func(c *Config) { c.Networks[0].Isolated = true }},
		{"WAN", func(c *Config) { c.Networks[0].Zone = "wan" }},
		{"UUID injection", func(c *Config) { c.Samba.Volumes[0].UUID = "x\nWhat=/dev/sda" }},
		{"UUID traversal", func(c *Config) { c.Samba.Volumes[0].UUID = "../../etc" }},
		{"duplicate UUID", func(c *Config) { v := c.Samba.Volumes[0]; v.ID = "other"; c.Samba.Volumes = append(c.Samba.Volumes, v) }},
		{"unsupported fs", func(c *Config) { c.Samba.Volumes[0].Filesystem = "swap" }},
		{"disabled volume", func(c *Config) { c.Samba.Volumes[0].Enabled = false }},
		{"missing volume", func(c *Config) { c.Samba.Volumes = nil }},
		{"missing user", func(c *Config) { c.Samba.Users = nil }},
		{"public share", func(c *Config) { c.Samba.Shares[0].Users = nil }},
		{"user injection", func(c *Config) { c.Samba.Users[0].Name = "a\nroot = *" }},
		{"share injection", func(c *Config) { c.Samba.Shares[0].Name = "x]\npath=/" }},
		{"reserved name", func(c *Config) { c.Samba.Shares[0].Name = "homes" }},
		{"weak password", func(c *Config) { c.Samba.Users[0].Password = "123" }},
		{"workgroup injection", func(c *Config) { c.Samba.Workgroup = "WORK;exec" }},
		{"unknown VPN", func(c *Config) { c.Samba.VPNs = []string{"none"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := sambaFixture()
			tc.change(c)
			r := &ValidationResult{}
			c.validateSamba(r)
			if !r.HasErrors() {
				t.Fatal("invalid config accepted")
			}
		})
	}
}
func TestSambaAllowsVPNOnlyAndRejectsProxy(t *testing.T) {
	c := sambaFixture()
	c.Samba.Networks = nil
	c.Samba.VPNs = []string{"vpn"}
	c.VPNServers = []VPNServer{{ID: "vpn", Enabled: true, Type: "wireguard", Subnet: "10.20.0.1/24"}}
	for _, kind := range []string{"wireguard", "ocserv", "ikev2", "l2tp"} {
		c.VPNServers[0].Type = kind
		r := &ValidationResult{}
		c.validateSamba(r)
		if r.HasErrors() {
			t.Fatal(kind, r.Problems)
		}
	}
	c.VPNServers[0].Type = "xray"
	r := &ValidationResult{}
	c.validateSamba(r)
	if !r.HasErrors() {
		t.Fatal("proxy is not an IP tunnel")
	}
}

func TestSambaReservesListenerPorts(t *testing.T) {
	for _, port := range []int{445, 3702} {
		c := sambaFixture()
		c.Samba.Discovery = true
		c.System.Panel.Port = port
		r := &ValidationResult{}
		c.validateVPNServers(r)
		if !r.HasErrors() {
			t.Fatalf("panel conflict on %d accepted", port)
		}
	}
	c := sambaFixture()
	c.Samba.Discovery = true
	c.DNS.Enabled = true
	c.DNS.Port = 3702
	r := &ValidationResult{}
	c.validateVPNServers(r)
	if !r.HasErrors() {
		t.Fatal("DNS/WS-Discovery conflict accepted")
	}
}
