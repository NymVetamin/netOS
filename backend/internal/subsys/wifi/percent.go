package wifi

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/netos-router/netos/internal/config"
)

// Percentage is linear RF power, not a percentage of the logarithmic dBm.
func percentMBm(maxDBm float64, percent int) int {
	// mac80211 accepts whole dBm only, even though nl80211 uses mBm.
	// Round down so the requested power is never exceeded.
	return 100 * int(math.Floor(maxDBm+10*math.Log10(float64(percent)/100)))
}

func txPowerWithinLimit(info string, limit int) bool {
	for _, line := range strings.Split(info, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "txpower" {
			v, err := strconv.ParseFloat(f[1], 64)
			return err == nil && v >= 0 && v*100 <= float64(limit)+1
		}
	}
	return false
}

func radioBandMatches(info, band string) bool {
	for _, line := range strings.Split(info, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "channel ") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			return false
		}
		frequency, err := strconv.Atoi(strings.TrimPrefix(f[2], "("))
		return err == nil && (band == "2.4" && frequency >= 2412 && frequency <= 2472 || band == "5" && frequency >= 5180 && frequency <= 5885)
	}
	return false
}

func (s *Subsystem) percentPower(ctx context.Context, radio config.WiFiRadio) (int, error) {
	hardware, err := ReadHardware(ctx, s.Runner, radio.Country)
	if err != nil {
		return 0, err
	}
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
			if b.Name == radio.Band {
				for _, ch := range b.Channels {
					if radio.Channel == 0 || ch.Number == radio.Channel {
						if power, ok := ch.PowerLimits[radio.Width]; ok {
							limit = math.Min(limit, power)
						}
					}
				}
			}
		}
	}
	if math.IsInf(limit, 1) {
		return 0, fmt.Errorf("не удалось определить допустимую мощность радио %s", radio.Device)
	}
	power := percentMBm(limit, radio.PowerPercent)
	if power < 0 {
		return 0, fmt.Errorf("выбранная мощность ниже поддерживаемого минимума 1 мВт")
	}
	return power, nil
}
