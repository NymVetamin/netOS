package vpnservers

import (
	"bytes"
	"encoding/json"
	"github.com/netos-router/netos/internal/config"
	"reflect"
	"testing"
)

func TestXrayPolicyOrderAndInputPreserved(t *testing.T) {
	cfg, server := xrayServerConfig()
	policy := func(id string, priority int, port string) config.Policy {
		return config.Policy{ID: id, Priority: priority, Enabled: true, VPNServer: server.ID, VPNPeer: "phone", Channel: "vpn", DstPort: port}
	}
	cfg.Policies = []config.Policy{
		policy("z", 20, "4"), policy("same", 10, "2"), policy("a", 10, "1"), policy("same", 10, "3"),
		policy("disabled", 0, "5"), policy("foreign", 0, "6"), policy("missing-peer", 0, "7"),
	}
	cfg.Policies[4].Enabled = false
	cfg.Policies[5].VPNServer = "other"
	cfg.Policies[6].VPNPeer = "absent"
	before, _ := json.Marshal(cfg)
	check := func(want []string) {
		t.Helper()
		data, err := RenderXray(server, cfg)
		if err != nil {
			t.Fatal(err)
		}
		var document struct {
			Routing struct {
				Rules []struct {
					Port string `json:"port"`
				} `json:"rules"`
			} `json:"routing"`
		}
		if err = json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, rule := range document.Routing.Rules {
			got = append(got, rule.Port)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("policy/default order got %v want %v", got, want)
		}
	}
	check([]string{"1", "2", "3", "4", ""})
	after, _ := json.Marshal(cfg)
	if !bytes.Equal(before, after) {
		t.Fatal("render mutated configuration")
	}
	cfg.Policies[0].Enabled = false
	check([]string{"1", "2", "3", ""})
	cfg.Policies[0].Enabled = true
	check([]string{"1", "2", "3", "4", ""})
	cfg.Policies = nil
	check([]string{""})
}
