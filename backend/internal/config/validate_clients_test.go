package config

import (
	"strings"
	"testing"
)

func TestValidateClientsRejectsBrokenReferencesAndDuplicates(t *testing.T) {
	cfg := Default()
	cfg.Clients = []Client{
		{ID: "phone", MAC: "AA:BB:CC:DD:EE:FF", Network: "missing", Channel: "missing", DownKbit: -1},
		{ID: "phone", MAC: "aa:bb:cc:dd:ee:ff", UpKbit: -1},
		{ID: "", MAC: "not-a-mac"},
		{ID: "too-fast", MAC: "00:11:22:33:44:55", DownKbit: 10_000_001, UpKbit: 10_000_001},
		{ID: "too-slow", MAC: "00:11:22:33:44:56", DownKbit: 63, UpKbit: 63},
	}

	result := cfg.Validate()
	var messages []string
	for _, problem := range result.Problems {
		messages = append(messages, problem.Path+": "+problem.Message)
	}
	got := strings.Join(messages, "\n")
	for _, want := range []string{
		"clients[0].network", "clients[0].channel", "clients[0].down_kbit",
		"clients[1].id", "clients[1].mac", "clients[1].up_kbit",
		"clients[2].id", "clients[2].mac",
		"clients[3].down_kbit", "clients[3].up_kbit",
		"clients[4].down_kbit", "clients[4].up_kbit",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("нет ошибки %s:\n%s", want, got)
		}
	}
}

func TestValidateClientsAcceptsBothRateBoundaries(t *testing.T) {
	cfg := Default()
	cfg.Interfaces = []Interface{{ID: "lan", Name: "lan0", Enabled: true}}
	cfg.Networks = []Network{{ID: "home", Interface: "lan", Enabled: true}}
	cfg.Clients = []Client{
		{ID: "minimum", MAC: "00:11:22:33:44:55", Network: "home", DownKbit: 64, UpKbit: 64},
		{ID: "maximum", MAC: "00:11:22:33:44:56", Network: "home", DownKbit: 10_000_000, UpKbit: 10_000_000},
	}
	for _, problem := range cfg.Validate().Problems {
		if strings.HasPrefix(problem.Path, "clients[") && problem.Severity == "error" {
			t.Fatalf("valid rate boundaries rejected: %+v", problem)
		}
	}
}

func TestValidateClientsWarnsWhenFirewallCannotEnforceBlock(t *testing.T) {
	cfg := Default()
	cfg.Firewall.Enabled = false
	cfg.Clients = []Client{{ID: "phone", MAC: "aa:bb:cc:dd:ee:ff", Blocked: true}}

	result := cfg.Validate()
	for _, problem := range result.Problems {
		if problem.Path == "clients" && problem.Severity == "warning" {
			return
		}
	}
	t.Fatalf("нет предупреждения о выключенном файрволле: %+v", result.Problems)
}

func TestNormalizeCanonicalizesClientMAC(t *testing.T) {
	cfg := Default()
	cfg.Clients = []Client{{ID: "phone", MAC: "AA-BB-CC-DD-EE-FF"}}
	cfg.Normalize()
	if cfg.Clients[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("MAC не приведён к канонической форме: %q", cfg.Clients[0].MAC)
	}
}
