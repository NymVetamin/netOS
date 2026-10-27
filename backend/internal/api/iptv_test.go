package api

import (
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/configdiff"
)

func TestIPTVServicesPermissions(t *testing.T) {
	c := config.Default()
	c.IPTV = config.IPTV{Enabled: true, Upstream: "provider", Networks: []string{"lan"}}
	expected := *c
	expected.IPTV.Enabled = false
	for _, level := range []string{"none", "view", "manage"} {
		r := limitedRequest(map[string]string{"services": level})
		shown, err := scopedConfig(r, c)
		if err != nil {
			t.Fatal(err)
		}
		if level == "none" && shown.IPTV.Enabled {
			t.Fatal("hidden IPTV configuration exposed")
		}
		shown.IPTV.Enabled = !shown.IPTV.Enabled
		merged, err := mergeScopedConfig(r, c, shown)
		if level != "manage" {
			if err == nil {
				t.Fatalf("%s can change IPTV", level)
			}
		} else if err != nil || !sameConfig(merged, &expected) {
			t.Fatalf("services change not preserved: %v", err)
		}
	}
}

func TestIPTVPlanUsesWANNameDespiteChannelIDCollision(t *testing.T) {
	c := config.Default()
	c.WANs = []config.WAN{{ID: "provider", Name: "Телевидение"}}
	c.Channels = []config.Channel{{ID: "provider", Name: "Другой канал"}}
	got := formatPlanValue(configdiff.Value{Present: true, Data: "provider"}, planField{Reference: "wan"}, c)
	if got != "Телевидение (provider)" {
		t.Fatal(got)
	}
}
