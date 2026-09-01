package config

import (
	"reflect"
	"testing"
)

func TestNormalizeCurrentSchemaDoesNotHideInvalidOrExplicitValues(t *testing.T) {
	cfg := Default()
	cfg.System.Panel.Port = 0
	cfg.System.Panel.CommitTimeout = 0
	cfg.System.Panel.TLS.Mode = ""
	cfg.System.NetworkBackend = ""
	cfg.IPv6.Mode = ""
	cfg.DNS.Port = 0
	cfg.DNS.LocalDomain = ""
	cfg.MultiWAN.Mode = ""
	cfg.Firewall.Zones = []Zone{}
	cfg.Firewall.OutputPolicy = ""
	cfg.QoS.WANs = []QoSWAN{{Diffserv: ""}}
	cfg.DDNS.AddressSource = ""
	cfg.DDNS.Interval = 0
	cfg.Interfaces = []Interface{{ID: "if-wan", Name: "eth0", Type: "physical", Enabled: true}}
	cfg.WANs = []WAN{{ID: "wan", Name: "WAN", Interface: "if-wan", Enabled: true, Proto: "dhcp"}}
	cfg.Channels[0].Mode = ""
	cfg.Channels[0].FailMode = ""
	cfg.Channels[0].Probe = Probe{}
	cfg.Networks = []Network{{ID: "lan", Zone: "", DHCPPool: DHCPPool{Enabled: true, LeaseTime: 0}}}
	cfg.Firewall.Rules = append(cfg.Firewall.Rules, FirewallRule{
		ID: "user-rule", Flow: "", Zone: "", DstZone: "lan", Action: "accept",
	})
	cfg.Firewall.NAT = []NATRule{{ID: "nat", Direction: ""}}

	cfg.Normalize()

	if cfg.Version != Version {
		t.Fatalf("schema version changed to %d", cfg.Version)
	}
	if cfg.System.Panel.Port != 0 || cfg.System.Panel.CommitTimeout != 0 || cfg.System.Panel.TLS.Mode != "" ||
		cfg.System.NetworkBackend != "" || cfg.IPv6.Mode != "" || cfg.DNS.Port != 0 || cfg.DNS.LocalDomain != "" ||
		cfg.MultiWAN.Mode != "" || len(cfg.Firewall.Zones) != 0 || cfg.Firewall.OutputPolicy != "" ||
		cfg.QoS.WANs[0].Diffserv != "" || cfg.DDNS.AddressSource != "" || cfg.DDNS.Interval != 0 {
		t.Fatalf("current scalar value was defaulted: %+v", cfg)
	}
	if w := cfg.WANs[0]; w.Index != 0 || w.Metric != 0 || w.Weight != 0 || !reflect.DeepEqual(w.Probe, Probe{}) {
		t.Fatalf("current WAN was defaulted: %+v", w)
	}
	if ch := cfg.Channels[0]; ch.Mode != "" || ch.FailMode != "" || !reflect.DeepEqual(ch.Probe, Probe{}) {
		t.Fatalf("current channel was defaulted: %+v", ch)
	}
	if n := cfg.Networks[0]; n.Zone != "" || n.DHCPPool.LeaseTime != 0 {
		t.Fatalf("current network was defaulted: %+v", n)
	}
	rule := cfg.Firewall.Rules[len(cfg.Firewall.Rules)-1]
	if rule.Flow != "" || rule.Zone != "" || rule.DstZone != "lan" {
		t.Fatalf("current firewall rule was rewritten: %+v", rule)
	}
	if cfg.Firewall.NAT[0].Direction != "" {
		t.Fatalf("current NAT rule was rewritten: %+v", cfg.Firewall.NAT[0])
	}
}

func TestNormalizeLegacySchemaBackfillsAndUpgrades(t *testing.T) {
	cfg := &Config{
		Version:  Version - 1,
		WANs:     []WAN{{ID: "wan"}},
		Channels: []Channel{{ID: "channel"}},
		Networks: []Network{{ID: "network"}},
		QoS:      QoS{WANs: []QoSWAN{{}}},
		Firewall: Firewall{
			Rules: []FirewallRule{{ID: "rule", Flow: "any", DstZone: "lan"}},
			NAT:   []NATRule{{ID: "nat"}},
		},
	}

	cfg.Normalize()

	if cfg.Version != Version {
		t.Fatalf("legacy schema remained at version %d", cfg.Version)
	}
	if cfg.System.Panel.Port != 8443 || cfg.System.Panel.CommitTimeout != 30 || cfg.System.Panel.TLS.Mode != "selfsigned" ||
		cfg.System.NetworkBackend != "netos" || cfg.IPv6.Mode != "off" || cfg.DNS.Port != 53 ||
		cfg.DNS.LocalDomain != "lan" || cfg.MultiWAN.Mode != "failover" || cfg.Firewall.OutputPolicy != "accept" ||
		len(cfg.Firewall.Zones) != len(DefaultZones()) || cfg.QoS.WANs[0].Diffserv != "diffserv4" ||
		cfg.DDNS.AddressSource != "interface" || cfg.DDNS.Interval != 300 {
		t.Fatalf("legacy scalar defaults incomplete: %+v", cfg)
	}
	if w := cfg.WANs[0]; w.Index != 1 || w.Metric != 100 || w.Weight != 1 || w.Probe.Type != "icmp" {
		t.Fatalf("legacy WAN defaults incomplete: %+v", w)
	}
	if ch := cfg.Channels[0]; ch.Mode != "tun" || ch.FailMode != "block" || ch.Probe.Type != "icmp" {
		t.Fatalf("legacy channel defaults incomplete: %+v", ch)
	}
	if n := cfg.Networks[0]; n.Zone != "lan" || n.DHCPPool.LeaseTime != 43200 {
		t.Fatalf("legacy network defaults incomplete: %+v", n)
	}
	rule := cfg.Firewall.Rules[len(cfg.Firewall.Rules)-1]
	if rule.ID != "rule" || rule.Flow != "in" || rule.Zone != "global" || rule.DstZone != "" {
		t.Fatalf("legacy firewall migration incomplete: %+v", rule)
	}
	if cfg.Firewall.NAT[0].Direction != "source" {
		t.Fatalf("legacy NAT migration incomplete: %+v", cfg.Firewall.NAT[0])
	}
}

func TestNormalizeCurrentInvalidValuesReachValidation(t *testing.T) {
	tests := []struct {
		name string
		path string
		edit func(*Config)
	}{
		{"panel port", "system.panel.port", func(c *Config) { c.System.Panel.Port = 0 }},
		{"commit timeout", "system.panel.commit_timeout", func(c *Config) { c.System.Panel.CommitTimeout = 0 }},
		{"TLS mode", "system.panel.tls.mode", func(c *Config) { c.System.Panel.TLS.Mode = "" }},
		{"network backend", "system.network_backend", func(c *Config) { c.System.NetworkBackend = "" }},
		{"IPv6 mode", "ipv6.mode", func(c *Config) { c.IPv6.Mode = "" }},
		{"DNS port", "dns.port", func(c *Config) { c.DNS.Port = 0 }},
		{"firewall output", "firewall.output_policy", func(c *Config) { c.Firewall.OutputPolicy = "" }},
		{"NAT direction", "firewall.nat[0].direction", func(c *Config) { c.Firewall.NAT = []NATRule{{ID: "nat"}} }},
		{"channel mode", "channels[0].mode", func(c *Config) { c.Channels[0].Mode = "" }},
		{"channel fail mode", "channels[0].fail_mode", func(c *Config) { c.Channels[0].FailMode = "" }},
		{"QoS diffserv", "qos.wans[0].diffserv", func(c *Config) { c.QoS.WANs = []QoSWAN{{Diffserv: ""}} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := Default()
			test.edit(cfg)
			cfg.Normalize()
			if !hasErrorAt(cfg.Validate(), test.path) {
				t.Fatalf("%s was hidden by normalization: %+v", test.path, cfg)
			}
		})
	}
}

func TestValidateRejectsUnknownSchemaVersion(t *testing.T) {
	cfg := Default()
	cfg.Version = Version + 1
	cfg.Normalize()
	if !hasErrorAt(cfg.Validate(), "version") {
		t.Fatalf("future schema version %d accepted", cfg.Version)
	}
}

func TestCustomTLSValidationMatchesImplementedServerMode(t *testing.T) {
	cfg := Default()
	cfg.System.Panel.TLS = TLS{Mode: "custom", CertFile: "/etc/netos/panel.crt", KeyFile: "/etc/netos/panel.key"}
	if result := cfg.Validate(); hasErrorAt(result, "system.panel.tls") {
		t.Fatalf("complete custom TLS configuration rejected: %+v", result.Problems)
	}

	for _, test := range []struct {
		name string
		tls  TLS
		path string
	}{
		{"missing certificate", TLS{Mode: "custom", KeyFile: "/key"}, "system.panel.tls.cert_file"},
		{"missing key", TLS{Mode: "custom", CertFile: "/cert"}, "system.panel.tls.key_file"},
		{"same file", TLS{Mode: "custom", CertFile: "/same", KeyFile: "/same"}, "system.panel.tls.key_file"},
		{"unsafe certificate", TLS{Mode: "custom", CertFile: "/cert\nnext", KeyFile: "/key"}, "system.panel.tls.cert_file"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := Default()
			cfg.System.Panel.TLS = test.tls
			if !hasErrorAt(cfg.Validate(), test.path) {
				t.Fatalf("invalid custom TLS accepted: %+v", cfg.System.Panel.TLS)
			}
		})
	}
}
