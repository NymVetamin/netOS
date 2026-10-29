package vpnservers

import (
	"encoding/json"
	"github.com/netos-router/netos/internal/config"
	"testing"
)

func TestXrayInternetBlockOverridesPolicyWithoutLosingIsolation(t *testing.T) {
	cfg, s := xrayServerConfig()
	s.Peers[0].Channel = config.InternetBlockChannel
	cfg.Networks = []config.Network{{ID: "local", Enabled: true, RouterAddress: "192.168.5.1/24"}, {ID: "isolated", Enabled: true, Isolated: true, RouterAddress: "192.168.6.1/24"}}
	cfg.Policies = []config.Policy{{ID: "override", Enabled: true, VPNServer: s.ID, Channel: "direct"}}
	data, err := RenderXray(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Routing struct {
			Rules []struct {
				OutboundTag string `json:"outboundTag"`
			}
		}
		Outbounds []struct {
			Tag      string
			Settings struct {
				FinalRules []struct {
					Action string
					IP     []string
				}
			}
		}
	}
	if err = json.Unmarshal(data, &d); err != nil {
		t.Fatal(err)
	}
	if d.Routing.Rules[0].OutboundTag != "block" {
		t.Fatal("policy bypasses block")
	}
	for _, o := range d.Outbounds {
		if o.Tag == "block" {
			r := o.Settings.FinalRules
			if len(r) != 3 || r[0].Action != "block" || r[1].Action != "allow" || r[2].Action != "block" {
				t.Fatalf("bad restriction: %+v", r)
			}
			return
		}
	}
	t.Fatal("missing restricted outbound")
}
