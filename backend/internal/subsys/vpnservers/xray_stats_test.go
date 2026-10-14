package vpnservers

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestXrayStatsArePrivateAndDoNotChangeRouting(t *testing.T) {
	server := config.VPNServer{ID: "srv", Index: 3, Type: "xray", Config: map[string]any{"protocol": "vmess"}, Peers: []config.VPNPeer{{ID: "phone", Enabled: true, Credentials: map[string]string{"uuid": "00000000-0000-4000-8000-000000000001"}}}}
	data, err := RenderXray(server, config.Default())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	api := doc["api"].(map[string]any)
	if api["listen"] != "/run/netos-xray-srv3/stats.sock" || len(api["services"].([]any)) != 1 || api["services"].([]any)[0] != "StatsService" {
		t.Fatal("API exposed unnecessary services or listener")
	}
	if len(doc["inbounds"].([]any)) != 1 || len(doc["outbounds"].([]any)) != 1 {
		t.Fatal("statistics changed data path")
	}
	unit := renderXrayUnit(server, "/var/lib/netos/generated/xray-srv3.json")
	for _, want := range []string{"RuntimeDirectory=netos-xray-srv3", "RuntimeDirectoryMode=0700", "UMask=0077", "ProtectSystem=strict"} {
		if !strings.Contains(unit, want) {
			t.Fatalf("missing %s", want)
		}
	}
	policy := doc["policy"].(map[string]any)["levels"].(map[string]any)["0"].(map[string]any)
	for _, key := range []string{"statsUserOnline", "statsUserUplink", "statsUserDownlink"} {
		if policy[key] != true {
			t.Fatal("missing", key)
		}
	}
}
