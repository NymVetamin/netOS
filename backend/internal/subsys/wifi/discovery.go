package wifi

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type ChannelOption struct {
	Number                                    int             `json:"number"`
	Frequency                                 int             `json:"frequency"`
	Widths                                    []int           `json:"widths"`
	MaxPower                                  float64         `json:"max_power"`
	PowerLimits                               map[int]float64 `json:"power_limits"`
	DFS                                       bool            `json:"dfs"`
	disabled, noIR, no40Plus, no40Minus, no80 bool
}
type BandOptions struct {
	Name          string          `json:"name"`
	Channels      []ChannelOption `json:"channels"`
	ht, ht40, vht bool
}
type RadioDevice struct {
	PHY         string        `json:"phy"`
	Device      string        `json:"device"`
	Interfaces  []string      `json:"interfaces"`
	AP          bool          `json:"ap"`
	AutoChannel bool          `json:"auto_channel"`
	Bands       []BandOptions `json:"bands"`
	index       string
}
type Hardware struct {
	Radios    []RadioDevice `json:"radios"`
	Countries []string      `json:"countries"`
	Country   string        `json:"country"`
}

var frequencyLine = regexp.MustCompile(`\* (\d+(?:\.\d+)?) MHz \[(\d+)\](.*)`)
var powerLine = regexp.MustCompile(`\(([-\d.]+) dBm\)`)

// ReadHardware is called only on demand, never by the dashboard poller.
// No reg-set, scans or changes to interfaces are performed.
func ReadHardware(ctx context.Context, runner system.Runner, country string) (Hardware, error) {
	result := Hardware{Radios: []RadioDevice{}, Countries: []string{}, Country: country}
	devs, err := runner.Run(ctx, "iw", "dev")
	if err != nil {
		return result, fmt.Errorf("не удалось определить Wi-Fi-устройства (нужен iw): %w", err)
	}
	phys, err := runner.Run(ctx, "iw", "phy")
	if err != nil {
		return result, fmt.Errorf("не удалось прочитать возможности Wi-Fi: %w", err)
	}
	result.Radios = parseHardware(phys, devs)
	db, err := readRegDB()
	if err != nil {
		return result, err
	}
	for c := range db {
		if len(c) == 2 && c != "00" {
			result.Countries = append(result.Countries, c)
		}
	}
	sort.Strings(result.Countries)
	if country == "" {
		reg, _ := runner.Run(ctx, "iw", "reg", "get")
		for _, line := range strings.Split(reg, "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "country" {
				country = strings.TrimSuffix(f[1], ":")
				break
			}
		}
		if _, ok := db[country]; !ok || country == "00" {
			country = "RU"
		}
	}
	if _, ok := db[country]; !ok {
		return result, fmt.Errorf("страна отсутствует в региональной базе Wi-Fi")
	}
	result.Country = country
	for i := range result.Radios {
		filterRadio(&result.Radios[i], db, country)
		if result.Radios[i].AP && result.Radios[i].Device != "" {
			_, err := runner.Run(ctx, "iw", "dev", result.Radios[i].Device, "survey", "dump")
			result.Radios[i].AutoChannel = err == nil
		}
	}
	return result, nil
}

func parseHardware(phys, devs string) []RadioDevice {
	radios := []RadioDevice{}
	var radio *RadioDevice
	var band *BandOptions
	var ch *ChannelOption
	modes := false
	for _, raw := range strings.Split(phys, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "Wiphy ") {
			radios = append(radios, RadioDevice{PHY: strings.TrimPrefix(line, "Wiphy "), Interfaces: []string{}, Bands: []BandOptions{}})
			radio = &radios[len(radios)-1]
			band = nil
			ch = nil
			modes = false
			continue
		}
		if radio == nil {
			continue
		}
		if strings.HasPrefix(line, "wiphy index:") {
			radio.index = strings.TrimSpace(strings.TrimPrefix(line, "wiphy index:"))
		}
		if line == "Supported interface modes:" {
			modes = true
			continue
		}
		if modes {
			if strings.HasPrefix(line, "* ") {
				if line == "* AP" {
					radio.AP = true
				}
				continue
			}
			modes = false
		}
		if strings.HasPrefix(line, "Band ") {
			radio.Bands = append(radio.Bands, BandOptions{Channels: []ChannelOption{}})
			band = &radio.Bands[len(radio.Bands)-1]
			ch = nil
			continue
		}
		if band == nil {
			continue
		}
		if strings.HasPrefix(line, "Capabilities:") {
			band.ht = true
		}
		if line == "HT20/HT40" {
			band.ht40 = true
		}
		if strings.HasPrefix(line, "VHT Capabilities") {
			band.vht = true
		}
		if m := frequencyLine.FindStringSubmatch(line); m != nil {
			mhz, _ := strconv.ParseFloat(m[1], 64)
			freq := int(mhz)
			number, _ := strconv.Atoi(m[2])
			name := ""
			if freq >= 2412 && freq <= 2472 {
				name = "2.4"
			}
			if freq >= 5180 && freq <= 5885 {
				name = "5"
			}
			if name == "" {
				ch = nil
				continue
			}
			band.Name = name
			power := 0.0
			if p := powerLine.FindStringSubmatch(m[3]); p != nil {
				power, _ = strconv.ParseFloat(p[1], 64)
			}
			band.Channels = append(band.Channels, ChannelOption{Number: number, Frequency: freq, MaxPower: power, Widths: []int{}})
			ch = &band.Channels[len(band.Channels)-1]
		}
		if ch != nil {
			ch.disabled = ch.disabled || strings.Contains(line, "disabled")
			ch.noIR = ch.noIR || strings.Contains(line, "no IR") || strings.Contains(line, "passive scan")
			ch.DFS = ch.DFS || strings.Contains(line, "radar detection")
			ch.no40Plus = ch.no40Plus || strings.Contains(line, "no HT40+")
			ch.no40Minus = ch.no40Minus || strings.Contains(line, "no HT40-")
			ch.no80 = ch.no80 || strings.Contains(line, "no 80MHz")
		}
	}
	// iw dev uses phy#index, while iw phy uses the driver-supplied wiphy name.
	// Match the explicit wiphy index when available; default phyN is common.
	byIndex := map[string]int{}
	for i, r := range radios {
		index := r.index
		if index == "" {
			index = strings.TrimPrefix(r.PHY, "phy")
		}
		byIndex[index] = i
	}
	var index, device string
	types := map[string]string{}
	for _, raw := range strings.Split(devs, "\n") {
		f := strings.Fields(raw)
		if len(f) == 0 {
			continue
		}
		if strings.HasPrefix(f[0], "phy#") {
			index = strings.TrimPrefix(f[0], "phy#")
		}
		if len(f) == 2 && f[0] == "Interface" {
			device = f[1]
			if i, ok := byIndex[index]; ok {
				radios[i].Interfaces = append(radios[i].Interfaces, f[1])
			}
		}
		if len(f) == 2 && f[0] == "type" {
			types[device] = f[1]
		}
	}
	for i := range radios {
		sort.Strings(radios[i].Interfaces)
		for _, device := range radios[i].Interfaces {
			if types[device] == "managed" || types[device] == "AP" || types[device] == "" {
				radios[i].Device = device
				break
			}
		}
	}
	return radios
}

func filterRadio(radio *RadioDevice, db regulatoryDB, country string) {
	bands := []BandOptions{}
	for _, b := range radio.Bands {
		if b.Name == "" || !b.ht || (b.Name == "5" && !b.vht) {
			continue
		}
		available := map[int]ChannelOption{}
		for _, c := range b.Channels {
			if b.Name == "5" && !config.ValidWiFi5GHzChannel(c.Number) {
				continue
			}
			if c.disabled || c.noIR {
				continue
			}
			p, ok := db.limit(country, c.Frequency, 20)
			if !ok {
				continue
			}
			c.MaxPower = math.Min(c.MaxPower, p)
			available[c.Number] = c
		}
		channels := []ChannelOption{}
		for _, c := range b.Channels {
			c, ok := available[c.Number]
			if !ok {
				continue
			}
			c.Widths = []int{20}
			c.PowerLimits = map[int]float64{20: c.MaxPower}
			sign := 1
			if secondaryChannelDirection(b.Name, c.Number) == "-" {
				sign = -1
			}
			other, hasOther := available[c.Number+sign*4]
			if b.ht40 && hasOther && (b.Name != "5" || c.Number <= 161) && !(sign == 1 && c.no40Plus || sign == -1 && c.no40Minus) {
				if power, ok := db.limit(country, (c.Frequency+other.Frequency)/2, 40); ok {
					c.Widths = append(c.Widths, 40)
					c.PowerLimits[40] = math.Min(power, math.Min(c.MaxPower, other.MaxPower))
				}
			}
			center := center80(c.Number)
			if b.vht && b.Name == "5" && !c.no80 && center != c.Number {
				valid := true
				powerLimit := c.MaxPower
				for _, n := range []int{center - 6, center - 2, center + 2, center + 6} {
					v, ok := available[n]
					if !ok || v.no80 {
						valid = false
					}
					powerLimit = math.Min(powerLimit, v.MaxPower)
				}
				if power, ok := db.limit(country, 5000+5*center, 80); valid && ok {
					c.Widths = append(c.Widths, 80)
					c.PowerLimits[80] = math.Min(powerLimit, power)
				}
			}
			channels = append(channels, c)
		}
		b.Channels = channels
		bands = append(bands, b)
	}
	radio.Bands = bands
}
