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
	data, err := RenderXray(testXrayChannel())
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
	outbound := testXrayChannel().Config["outbound"].(map[string]any)
	if _, changed := outbound["tag"]; changed {
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
