//go:build linux

package wifi

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationSelectedRadioPowerDiscovery(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root required")
	}
	for _, command := range []string{"iw", "modprobe"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skip(command + " unavailable")
		}
	}
	if _, err := os.Stat("/sys/module/mac80211_hwsim"); err == nil {
		t.Skip("existing hwsim instance")
	}
	ctx := context.Background()
	runner := system.NewExec()
	before, err := runner.Run(ctx, "iw", "dev")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(before) != "" {
		t.Skip("existing radios must not be changed")
	}
	reg, err := runner.Run(ctx, "iw", "reg", "get")
	if err != nil {
		t.Fatal(err)
	}
	originalCountry := ""
	for _, line := range strings.Split(reg, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "country" {
			originalCountry = strings.TrimSuffix(f[1], ":")
			break
		}
	}
	if originalCountry == "" {
		t.Fatal("cannot restore original regulatory country")
	}
	t.Cleanup(func() {
		if _, err := runner.Run(ctx, "iw", "reg", "set", originalCountry); err != nil {
			t.Error(err)
		}
	})
	if _, err := runner.Run(ctx, "modprobe", "mac80211_hwsim", "radios=2"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := runner.Run(ctx, "modprobe", "-r", "mac80211_hwsim"); err != nil {
			t.Error(err)
		}
	})
	for _, args := range [][]string{{"reg", "reload"}, {"reg", "set", "US"}} {
		if _, err := runner.Run(ctx, "iw", args...); err != nil {
			t.Fatal(err)
		}
	}
	var hardware Hardware
	for i := 0; i < 20; i++ {
		hardware, err = ReadHardware(ctx, runner, "US")
		if err != nil {
			t.Fatal(err)
		}
		if len(hardware.Radios) == 2 && len(hardware.Radios[0].Bands) > 0 && len(hardware.Radios[0].Bands[0].Channels) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	var radios []config.WiFiRadio
	for _, r := range hardware.Radios {
		if !r.AP || r.Device == "" || len(r.Bands) == 0 || len(r.Bands[0].Channels) == 0 {
			t.Fatalf("unusable hwsim radio: %+v", r)
		}
		radios = append(radios, config.WiFiRadio{Device: r.Device, Country: "US", Band: r.Bands[0].Name, Channel: r.Bands[0].Channels[0].Number, Width: 20, PowerPercent: 50})
	}
	if len(radios) != 2 {
		t.Fatalf("radios=%d", len(radios))
	}
	// PHY names are not necessarily phyN; index-scoped iw must still work.
	if _, err := runner.Run(ctx, "iw", "phy", hardware.Radios[0].PHY, "set", "name", "netos-power-test"); err != nil {
		t.Fatal(err)
	}
	old := func() []int {
		var out []int
		for _, radio := range radios {
			h, err := ReadHardware(ctx, runner, radio.Country)
			if err != nil {
				t.Fatal(err)
			}
			v, err := legacyHardwarePower(h, radio)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, v)
		}
		return out
	}
	current := func() []int {
		p := &radioPowerLimits{}
		var out []int
		for _, radio := range radios {
			v, err := p.percentPower(ctx, runner, radio)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, v)
		}
		return out
	}
	commands := 0
	runner.OnCommand = func(string, []string) { commands++ }
	for repeat := 0; repeat < 3; repeat++ {
		commands = 0
		start := time.Now()
		want := old()
		oldTime, oldCalls := time.Since(start), commands
		commands = 0
		start = time.Now()
		got := current()
		newTime, newCalls := time.Since(start), commands
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("power changed: %v -> %v", want, got)
			}
		}
		if oldCalls != 8 || newCalls != 4 {
			t.Fatalf("commands: %d -> %d", oldCalls, newCalls)
		}
		t.Logf("two radios: old=%s/%d commands current=%s/%d commands power=%v", oldTime, oldCalls, newTime, newCalls, got)
	}
	// A new invocation must observe a changed requested percentage.
	radios[0].PowerPercent = 100
	want, got := old(), current()
	for i := range got {
		if want[i] != got[i] {
			t.Fatalf("repeat changed: %v -> %v", want, got)
		}
	}
	limits := &radioPowerLimits{}
	missing := radios[0]
	missing.Device = "netos-absent"
	if _, err := limits.percentPower(ctx, runner, missing); err == nil {
		t.Fatal("missing device accepted")
	}
	recovered, err := limits.percentPower(ctx, runner, radios[0])
	if err != nil || recovered != want[0] {
		t.Fatalf("retry after missing device: %d %v", recovered, err)
	}
}
