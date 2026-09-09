package config

import "testing"

func TestEnabledLANRejectsDisabledInterface(t *testing.T) {
	cfg := Default()
	cfg.Interfaces = []Interface{{ID: "lan-port", Name: "eth1", Type: "physical"}}
	cfg.Networks = []Network{{ID: "lan", Name: "LAN", Enabled: true, Interface: "lan-port", RouterAddress: "192.0.2.1/24", Zone: "lan"}}
	if !hasRemainingProblem(cfg, "networks[0].interface", "error") {
		t.Fatal("enabled LAN accepted on a disabled port; Apply will raise it again and fail interface health")
	}
	cfg.Networks[0].Enabled = false
	if hasRemainingProblem(cfg, "networks[0].interface", "error") {
		t.Fatal("disabled LAN should allow its port to be disabled")
	}
	cfg.Networks[0].Enabled = true
	cfg.Interfaces[0].Enabled = true
	if hasRemainingProblem(cfg, "networks[0].interface", "error") {
		t.Fatal("enabled LAN on an enabled port rejected")
	}
}

func TestInterfaceMACRejectsUnusableEthernetAddresses(t *testing.T) {
	cfg := Default()
	cfg.Interfaces = []Interface{{ID: "port", Name: "eth1", Type: "physical", Enabled: true}}
	for _, mac := range []string{"01:91:13:00:00:06", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "02:91:13:00:00:00:00:06"} {
		cfg.Interfaces[0].MAC = mac
		if !hasRemainingProblem(cfg, "interfaces[0].mac", "error") {
			t.Errorf("accepted MAC %s that an Ethernet interface cannot use", mac)
		}
	}
	for _, mac := range []string{"", "02:91:13:00:00:06", "fa:16:3e:18:e1:b6"} {
		cfg.Interfaces[0].MAC = mac
		if hasRemainingProblem(cfg, "interfaces[0].mac", "error") {
			t.Errorf("valid MAC override/reset rejected: %q", mac)
		}
	}
}

func TestInterfaceMACRejectsDuplicateOverrides(t *testing.T) {
	cfg := Default()
	cfg.Interfaces = []Interface{
		{ID: "first", Name: "eth0", Type: "physical", MAC: "02:91:13:00:00:06", Enabled: true},
		{ID: "second", Name: "eth1", Type: "physical", MAC: "02-91-13-00-00-06", Enabled: true},
	}
	if !hasRemainingProblem(cfg, "interfaces[1].mac", "error") {
		t.Fatal("duplicate interface MAC overrides accepted")
	}

	cfg.Interfaces[1].MAC = "02:91:13:00:00:07"
	if hasRemainingProblem(cfg, "interfaces[1].mac", "error") {
		t.Fatal("distinct interface MAC overrides rejected")
	}
}
