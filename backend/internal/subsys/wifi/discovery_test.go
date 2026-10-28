package wifi

import (
	"encoding/binary"
	"math"
	"strings"
	"testing"
)

const phyFixture = `Wiphy phy0
 Supported interface modes:
  * managed
  * AP
 Band 1:
  Capabilities: 0x1
   HT20/HT40
  Frequencies:
   * 2412 MHz [1] (20.0 dBm)
   * 2432 MHz [5] (20.0 dBm)
   * 2472 MHz [13] (20.0 dBm) (no IR)
 Band 2:
  Capabilities: 0x1
   HT20/HT40
  VHT Capabilities (0x1):
  Frequencies:
   * 5180 MHz [36] (23.0 dBm)
   * 5200 MHz [40] (23.0 dBm)
   * 5220 MHz [44] (23.0 dBm)
   * 5240 MHz [48] (23.0 dBm)
   * 5260 MHz [52] (disabled)
Wiphy phy1
 Supported interface modes:
  * managed
 Band 1:
  Capabilities: 0x1
  Frequencies:
   * 2412 MHz [1] (17.0 dBm)
`

func TestDiscoveryGroupsBSSAndFiltersHardwareAndCountry(t *testing.T) {
	radios := parseHardware(phyFixture, "phy#0\n Interface wlan0-n1\n Interface wlan0\nphy#1\n Interface wlan1\n")
	if len(radios) != 2 || !radios[0].AP || radios[1].AP || radios[0].Device != "wlan0" || len(radios[0].Interfaces) != 2 {
		t.Fatalf("bad radios: %+v", radios)
	}
	db := regulatoryDB{"US": {{2402, 2472, 40, 18, 0}, {5170, 5250, 80, 20, 0}}}
	filterRadio(&radios[0], db, "US")
	if len(radios[0].Bands) != 2 || len(radios[0].Bands[0].Channels) != 2 {
		t.Fatalf("bad bands: %+v", radios[0])
	}
	c := radios[0].Bands[1].Channels[0]
	if c.Number != 36 || c.Frequency != 5180 || c.MaxPower != 20 || len(c.Widths) != 3 {
		t.Fatalf("bad channel: %+v", c)
	}
	radios = parseHardware(strings.ReplaceAll(phyFixture, "HT20/HT40", "HT20"), "")
	filterRadio(&radios[0], db, "US")
	if len(radios[0].Bands[0].Channels[0].Widths) != 1 {
		t.Fatal("advertised unsupported HT40")
	}
}

func TestRegDBBoundsAndCountryRules(t *testing.T) {
	b := make([]byte, 40)
	copy(b, "RGDB")
	binary.BigEndian.PutUint32(b[4:8], 20)
	copy(b[8:10], "US")
	binary.BigEndian.PutUint16(b[10:12], 4)
	b[16] = 3
	b[17] = 1
	binary.BigEndian.PutUint16(b[20:22], 6)
	b[24] = 16
	binary.BigEndian.PutUint16(b[26:28], 2000)
	binary.BigEndian.PutUint32(b[28:32], 2402000)
	binary.BigEndian.PutUint32(b[32:36], 2472000)
	binary.BigEndian.PutUint32(b[36:40], 40000)
	db, err := parseRegDB(b)
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := db.limit("US", 2412, 20); !ok || p != 20 {
		t.Fatalf("wrong rule: %v %v", p, ok)
	}
	if _, ok := db.limit("US", 2472, 20); ok {
		t.Fatal("out-of-country channel accepted")
	}
	for i := 0; i < len(b); i++ {
		if _, err := parseRegDB(b[:i]); err == nil {
			t.Fatalf("truncation %d accepted", i)
		}
	}
	for i := 0; i < len(b); i++ {
		copyB := append([]byte(nil), b...)
		copyB[i] = 255
		parseRegDB(copyB)
	} // malformed offsets must not panic
}

func TestPowerPercentUsesLinearWatts(t *testing.T) {
	for _, tc := range []struct{ percent, want int }{{100, 2000}, {50, 1600}, {25, 1300}, {10, 1000}, {1, 0}} {
		if got := percentMBm(20, tc.percent); math.Abs(float64(got-tc.want)) > 1 {
			t.Fatalf("%d%%: got %d want %d", tc.percent, got, tc.want)
		}
	}
}

func TestAutomaticChannelRenderAndRuntime(t *testing.T) {
	cfg := wifiConfig()
	r := cfg.WiFi[0]
	r.Channel = 0
	text, err := RenderRadio(r, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(text), "channel=0\n") || strings.Contains(string(text), "vht_oper_centr_freq_seg0_idx=0") {
		t.Fatal(string(text))
	}
	if !radioInfoMatches("Interface wlan0\n type AP\n ssid test\n channel 44 (5220 MHz)", "wlan0", 0, "test") {
		t.Fatal("ACS-selected channel rejected")
	}
}

func TestDiscoveryDecimalFrequenciesAndRenamedPHY(t *testing.T) {
	phy := strings.ReplaceAll(phyFixture, "Wiphy phy0", "Wiphy custom-name\n wiphy index: 7")
	phy = strings.ReplaceAll(phy, "2412 MHz", "2412.0 MHz")
	radios := parseHardware(phy, "phy#7\n Interface mon0\n type monitor\n Interface wlan0\n type managed\n")
	if radios[0].Device != "wlan0" || radios[0].Bands[0].Channels[0].Frequency != 2412 {
		t.Fatalf("wrong identity: %+v", radios[0])
	}
}

func TestPowerLimitAndACSBandHealth(t *testing.T) {
	if !txPowerWithinLimit("txpower 16.00 dBm", 1600) || txPowerWithinLimit("txpower 20.00 dBm", 1600) || txPowerWithinLimit("", 1600) {
		t.Fatal("power health mismatch")
	}
	if !radioBandMatches("channel 36 (5180 MHz)", "5") || radioBandMatches("channel 1 (2412 MHz)", "5") {
		t.Fatal("ACS wrong-band accepted")
	}
}
