package wifi

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type powerDiscoveryRunner struct {
	phy, info, fail string
	calls           []string
}

func (r *powerDiscoveryRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, command)
	if command == r.fail {
		return "", errors.New("test failure")
	}
	switch command {
	case "iw dev wlan0 info":
		return r.info, nil
	case "iw phy#0 info":
		return r.phy, nil
	case "iw reg get":
		return "country US: DFS-FCC", nil
	default:
		return "", fmt.Errorf("unexpected command %s", command)
	}
}
func (r *powerDiscoveryRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

// The old full-discovery calculation, retained as an equivalence oracle.
func legacyHardwarePower(hardware Hardware, radio config.WiFiRadio) (int, error) {
	limit := math.Inf(1)
	for _, r := range hardware.Radios {
		matches := false
		for _, device := range r.Interfaces {
			if device == radio.Device {
				matches = true
			}
		}
		if !matches {
			continue
		}
		for _, b := range r.Bands {
			if b.Name != radio.Band {
				continue
			}
			for _, ch := range b.Channels {
				if radio.Channel == 0 || ch.Number == radio.Channel {
					if power, ok := ch.PowerLimits[radio.Width]; ok {
						limit = math.Min(limit, power)
					}
				}
			}
		}
	}
	if math.IsInf(limit, 1) {
		return 0, errors.New("unavailable")
	}
	power := percentMBm(limit, radio.PowerPercent)
	if power < 0 {
		return 0, errors.New("below minimum")
	}
	return power, nil
}

func TestSelectedRadioPowerMatchesFullDiscovery(t *testing.T) {
	db := regulatoryDB{"US": {{2402, 2472, 40, 18, 0}, {5170, 5250, 80, 20, 0}}, "RU": {{2402, 2482, 40, 20, 0}, {5170, 5250, 80, 23, 0}}}
	phy := strings.Split(phyFixture, "Wiphy phy1")[0]
	for _, country := range []string{"US", "RU"} {
		old := Hardware{Radios: parseHardware(phyFixture, "phy#0\n Interface wlan0\nphy#1\n Interface wlan1\n")}
		for i := range old.Radios {
			filterRadio(&old.Radios[i], db, country)
		}
		for _, band := range []string{"2.4", "5"} {
			for _, channel := range []int{0, 1, 5, 13, 36, 40, 52} {
				for _, width := range []int{20, 40, 80} {
					for _, percent := range []int{1, 10, 50, 100} {
						radio := config.WiFiRadio{Device: "wlan0", Country: country, Band: band, Channel: channel, Width: width, PowerPercent: percent}
						runner := &powerDiscoveryRunner{phy: phy, info: "Interface wlan0\n wiphy 0\n"}
						got, err := (&radioPowerLimits{db: db}).percentPower(context.Background(), runner, radio)
						want, wantErr := legacyHardwarePower(old, radio)
						if (err != nil) != (wantErr != nil) || err == nil && got != want {
							t.Fatalf("%+v: got %d/%v want %d/%v", radio, got, err, want, wantErr)
						}
						if len(runner.calls) != 2 {
							t.Fatal(runner.calls)
						}
					}
				}
			}
		}
	}
}

func TestSelectedRadioPowerFreshnessFailureAndRetry(t *testing.T) {
	db := regulatoryDB{"US": {{2402, 2472, 40, 30, 0}}}
	runner := &powerDiscoveryRunner{phy: strings.ReplaceAll(strings.Split(phyFixture, "Wiphy phy1")[0], "Wiphy phy0", "Wiphy custom-name"), info: "Interface wlan0\n wiphy 0\n"}
	p := &radioPowerLimits{db: db}
	radio := config.WiFiRadio{Device: "wlan0", Country: "US", Band: "2.4", Channel: 1, Width: 20, PowerPercent: 50}
	read := func() int {
		t.Helper()
		got, err := p.percentPower(context.Background(), runner, radio)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := read(); got != 1600 {
		t.Fatal(got)
	}
	for _, failed := range []string{"iw dev wlan0 info", "iw phy#0 info"} {
		runner.fail = failed
		if _, err := p.percentPower(context.Background(), runner, radio); err == nil {
			t.Fatal("failure ignored")
		}
		runner.fail = ""
		if got := read(); got != 1600 {
			t.Fatal(got)
		}
	}
	runner.phy = strings.ReplaceAll(runner.phy, "20.0 dBm", "10.0 dBm")
	if got := read(); got != 600 {
		t.Fatalf("stale kernel capability: %d", got)
	}
	runner.info = "Interface wlan0\n"
	if _, err := p.percentPower(context.Background(), runner, radio); err == nil {
		t.Fatal("missing PHY identity accepted")
	}
	runner.info = "Interface wlan0\n wiphy 0\n"
	runner.phy = ""
	if _, err := p.percentPower(context.Background(), runner, radio); err == nil {
		t.Fatal("empty PHY accepted")
	}
}
