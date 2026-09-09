package wifi

import (
	"context"
	"strings"
	"testing"
)

func TestPowerChangeTargetsPhysicalRadioWithoutRestart(t *testing.T) {
	runner := &fakeRunner{active: true, enabled: true, outputs: map[string]string{
		"iw dev wlan0 info": "Interface wlan0\n\twiphy 7\n\tssid netOS\n\ttype AP\n\tchannel 36 (5180 MHz)\n\ttxpower 18.00 dBm\n",
	}}
	s := testWiFiSubsystem(t, runner)
	cfg := wifiConfig() // Two BSSes share the physical radio.
	if err := s.applyRadio(context.Background(), cfg, cfg.WiFi[0]); err != nil {
		t.Fatal(err)
	}
	for _, power := range []int{12, 0} {
		runner.commands = nil
		cfg.WiFi[0].TxPower = power
		if err := s.applyRadio(context.Background(), cfg, cfg.WiFi[0]); err != nil {
			t.Fatal(err)
		}
		want := "iw phy#7 set txpower fixed 1200"
		if power == 0 {
			want = "iw phy#7 set txpower auto"
		}
		found := false
		for _, command := range runner.commands {
			found = found || command == want
			if strings.Contains(command, "systemctl restart") || strings.Contains(command, "iw dev wlan0 set txpower") {
				t.Fatalf("power-only change used wrong operation: %s", command)
			}
		}
		if !found {
			t.Fatalf("missing %q: %v", want, runner.commands)
		}
	}
}
