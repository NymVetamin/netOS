package config

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestUnknownDisabledChannelSurvivesWithoutBecomingUsable(t *testing.T) {
	cfg := Default()
	ch := Channel{ID: "future", Index: 1, Name: "Saved future channel", Type: "future-protocol", Mode: "tun", FailMode: "block",
		Config: map[string]any{"nested": map[string]any{"list": []any{"keep", float64(17), true}}}}
	cfg.Channels = append(cfg.Channels, ch)
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var loaded Config
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatal(err)
	}
	loaded.Normalize()
	if !reflect.DeepEqual(loaded.Channels[1], ch) {
		t.Fatalf("saved channel changed: %+v", loaded.Channels[1])
	}
	result := loaded.Validate()
	if result.HasErrors() {
		t.Fatalf("disabled unknown channel blocks unrelated settings: %+v", result.Problems)
	}
	warned := false
	for _, p := range result.Problems {
		warned = warned || p.Path == "channels[1].type" && p.Severity == "warning"
	}
	if !warned {
		t.Fatal("unknown type not reported")
	}
	loaded.Channels[1].Enabled = true
	if !hasErrorAt(loaded.Validate(), "channels[1].enabled") {
		t.Fatal("unknown channel became usable")
	}
	loaded.Channels[1].Enabled = false
	wg := validWireGuardChannel()
	wg.Index = 2
	wg.FailMode, wg.Fallback = "fallback", "direct"
	loaded.Components = []Component{{ID: "wireguard", Installed: true}}
	loaded.Channels = append(loaded.Channels, wg)
	if loaded.Validate().HasErrors() {
		t.Fatal("valid direct fallback control rejected")
	}
	loaded.Channels[2].Fallback = ch.ID
	if !hasErrorAt(loaded.Validate(), "channels") {
		t.Fatal("disabled unknown channel accepted as fallback")
	}
}
