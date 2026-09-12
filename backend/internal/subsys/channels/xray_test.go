package channels

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func testXrayChannel() config.Channel {
	return config.Channel{
		ID: "xray", Index: 3, Name: "Xray test", Enabled: true,
		Type: "xray", Mode: "tun", FailMode: "block",
		Config: map[string]any{
			"mtu": 1380,
			"outbound": map[string]any{
				"protocol":       "vless",
				"settings":       map[string]any{"vnext": []any{map[string]any{"address": "vpn.example.com", "port": 443}}},
				"streamSettings": map[string]any{"network": "tcp", "security": "reality"},
			},
		},
	}
}

func TestRenderXrayOwnsTunAndPreservesOutbound(t *testing.T) {
	ch := testXrayChannel()
	before, _ := json.Marshal(ch)
	data, err := RenderXray(ch)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{`"protocol": "tun"`, `"name": "tun-ch3"`, `"mtu": 1380`, `"gateway": [`, `"198.18.0.13/30"`, `"security": "reality"`, `"outboundTag": "proxy"`} {
		if !strings.Contains(text, want) {
			t.Errorf("нет %s:\n%s", want, text)
		}
	}
	proxy := document["outbounds"].([]any)[0].(map[string]any)
	stream := proxy["streamSettings"].(map[string]any)
	if stream["sockopt"].(map[string]any)["mark"] != float64(0x40000000) {
		t.Fatal("proxy transport may re-enter DNS policy")
	}
	after, _ := json.Marshal(ch)
	if string(before) != string(after) {
		t.Fatal("renderer mutated the revision config")
	}
}

func TestXrayUnitIsHardenedAndValidatesConfig(t *testing.T) {
	unit := renderXrayUnit(testXrayChannel(), "/var/lib/netos/generated/xray-ch3.json")
	for _, want := range []string{
		"ExecStartPre=/usr/local/bin/xray run -test -config", "ExecStart=/usr/local/bin/xray run -config",
		"NoNewPrivileges=true", "ProtectSystem=strict", "CapabilityBoundingSet=CAP_NET_ADMIN",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("нет %q:\n%s", want, unit)
		}
	}
}

func TestRenderWireGuardDoesNotAllowGlobalNetworkMutation(t *testing.T) {
	for _, mode := range []string{"omitted", "false", "true"} {
		t.Run(mode, func(t *testing.T) {
			ch := testXrayChannel()
			settings := map[string]any{"secretKey": "fixture", "address": []any{"192.0.2.2/32"}}
			if mode != "omitted" {
				settings["noKernelTun"] = mode == "true"
			}
			ch.Config["outbound"] = map[string]any{"protocol": "wireguard", "settings": settings}
			before, _ := json.Marshal(ch)
			data, err := RenderXray(ch)
			if err != nil {
				t.Fatal(err)
			}
			var document struct {
				Outbounds []struct {
					Settings map[string]any `json:"settings"`
				} `json:"outbounds"`
			}
			if err := json.Unmarshal(data, &document); err != nil {
				t.Fatal(err)
			}
			if len(document.Outbounds) != 1 || document.Outbounds[0].Settings["noKernelTun"] != true {
				t.Fatal("WireGuard outbound can change router-wide sysctls")
			}
			if document.Outbounds[0].Settings["secretKey"] != "fixture" {
				t.Fatal("lost WireGuard settings")
			}
			after, _ := json.Marshal(ch)
			if string(before) != string(after) {
				t.Fatal("renderer mutated saved outbound")
			}
		})
	}
}
