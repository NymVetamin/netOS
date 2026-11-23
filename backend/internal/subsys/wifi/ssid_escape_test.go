package wifi

import (
	"context"
	"strings"
	"testing"
)

func TestRadioInfoEscapedSSID(t *testing.T) {
	for _, tc := range []struct {
		printed, wanted string
		match           bool
	}{
		{`Home\x5cLab`, `Home\Lab`, true},
		{`\xd0\x94\xd0\xbe\xd0\xbc`, "Дом", true},
		{`\x20Home\x20`, " Home ", true},
		{`Home Lab`, "Home Lab", true},
		{`Home\x5cx41`, `Home\x41`, true},
		{`Home\x5cx41`, `HomeA`, false},
		{`Home\x5cLab`, `Home\x5cLab`, false},
		{`Home\x`, `Home`, false},
		{`Home\xgg`, `Home`, false},
		{`\xgg`, "X", false},
		{`\x+1`, "\x01", false},
		{`\x1`, "\x01", false},
		{`\n`, "\n", false},
		{`Home\n`, "Home\n", false},
		{`Home`, `Other`, false},
		{`Home extra`, `Home`, false},
	} {
		t.Run(tc.printed+"/"+tc.wanted, func(t *testing.T) {
			info := "Interface wlan0\n\ttype AP\n\tchannel 36\n\tssid " + tc.printed + "\n"
			if got := radioInfoMatches(info, "wlan0", 36, tc.wanted); got != tc.match {
				t.Fatalf("match=%v want %v", got, tc.match)
			}
		})
	}
}

func TestEscapedSSIDApplyPlanHealthAndRetry(t *testing.T) {
	cfg := wifiConfig()
	cfg.WiFi[0].SSIDs[0].SSID = `Home\Lab`
	runner := &fakeRunner{outputs: map[string]string{"iw dev wlan0 info": "Interface wlan0\n\ttype AP\n\tchannel 36\n\tssid Home\\x5cLab\n\ttxpower 18.00 dBm\n"}}
	s := testWiFiSubsystem(t, runner)
	ctx := context.Background()
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	for repeat := 0; repeat < 2; repeat++ {
		runner.commands = nil
		if err := s.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.Join(runner.commands, "\n"), "systemctl restart ") {
			t.Fatal("escaped SSID caused unnecessary restart")
		}
		if actions, err := s.PlanContext(ctx, cfg, cfg); err != nil || len(actions) != 0 {
			t.Fatalf("plan=%v err=%v", actions, err)
		}
		if err := s.Health(ctx, cfg); err != nil {
			t.Fatal(err)
		}
	}
	correct := runner.outputs["iw dev wlan0 info"]
	runner.outputs["iw dev wlan0 info"] = strings.Replace(correct, `Home\x5cLab`, `Wrong`, 1)
	if s.health(ctx, cfg, 1) == nil {
		t.Fatal("actual SSID drift ignored")
	}
	runner.commands = nil
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(runner.commands, "\n"), "systemctl restart ") {
		t.Fatal("actual drift did not restart")
	}
	runner.outputs["iw dev wlan0 info"] = correct
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
}
