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
	} {
		if !strings.Contains(got, want) {
			t.Errorf("нет ошибки %s:\n%s", want, got)
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
