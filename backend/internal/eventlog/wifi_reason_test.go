package eventlog

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestWiFiReasonBelongsToInterfaceAndMAC(t *testing.T) {
	l, lan := lanFixture()
	at := time.Unix(1000, 0)
	lan.WiFi(at, "wlan0: STA AA:BB:CC:DD:EE:01 IEEE 802.11: disassociated due to inactivity")
	lan.WiFi(at.Add(time.Second), "wlan1: AP-STA-DISCONNECTED aa:bb:cc:dd:ee:01")
	lan.WiFi(at.Add(2*time.Second), "wlan0: AP-STA-DISCONNECTED aa:bb:cc:dd:ee:01")
	got := messages(l, WiFi)
	if len(got) != 2 || strings.Contains(got[0], "долго не отвечал") || !strings.Contains(got[1], "долго не отвечал") {
		t.Fatalf("cross-radio reason: %v", got)
	}
	lan.WiFi(at.Add(3*time.Second), "wlan0: AP-STA-DISCONNECTED aa:bb:cc:dd:ee:01")
	got = messages(l, WiFi)
	if strings.Contains(got[len(got)-1], "долго не отвечал") {
		t.Fatal("consumed reason reused")
	}
}

func TestWiFiConcurrentRadioReasons(t *testing.T) {
	l, lan := lanFixture()
	at := time.Unix(1000, 0)
	for _, line := range []string{
		"wlan0: STA aa:bb:cc:dd:ee:01 IEEE 802.11: deauthenticated due to inactivity",
		"wlan1: STA aa:bb:cc:dd:ee:01 IEEE 802.11: disassociated due to local deauth request",
		"wlan0: AP-STA-DISCONNECTED aa:bb:cc:dd:ee:01",
		"wlan1: AP-STA-DISCONNECTED aa:bb:cc:dd:ee:01",
	} {
		lan.WiFi(at, line)
	}
	got := messages(l, WiFi)
	if len(got) != 2 || !strings.Contains(got[0], "долго не отвечал") || !strings.Contains(got[1], "отключён точкой доступа") {
		t.Fatal(got)
	}
}

func TestWiFiReasonExpirationAndUnknown(t *testing.T) {
	for _, reason := range []string{"inactivity", "unknown reason", ""} {
		for _, age := range []time.Duration{2 * time.Second, 3 * time.Second, 4 * time.Second} {
			l, lan := lanFixture()
			at := time.Unix(1000, 0)
			line := "wlan0: STA aa:bb:cc:dd:ee:01 IEEE 802.11: deauthenticated"
			if reason != "" {
				line += " due to " + reason
			}
			lan.WiFi(at, line)
			lan.WiFi(at.Add(age), "wlan0: AP-STA-DISCONNECTED aa:bb:cc:dd:ee:01")
			got := messages(l, WiFi)
			if len(got) != 1 || strings.Contains(got[0], "долго не отвечал") != (reason == "inactivity" && age < 3*time.Second) {
				t.Fatal(reason, age, got)
			}
		}
	}
}

func TestWiFiReasonDoesNotCrossClientsAndRemainsBounded(t *testing.T) {
	l, lan := lanFixture()
	at := time.Unix(1000, 0)
	lan.WiFi(at, "wlan0: STA aa:bb:cc:dd:ee:01 IEEE 802.11: deauthenticated due to inactivity")
	lan.WiFi(at, "wlan0: AP-STA-DISCONNECTED aa:bb:cc:dd:ee:02")
	if got := messages(l, WiFi); len(got) != 1 || strings.Contains(got[0], "долго не отвечал") {
		t.Fatal(got)
	}
	for i := 0; i <= lanStateLimit; i++ {
		lan.WiFi(at, fmt.Sprintf("wlan%d: STA aa:bb:cc:dd:ee:01 IEEE 802.11: deauthenticated due to inactivity", i))
	}
	if len(lan.reasons) > lanStateLimit {
		t.Fatalf("unbounded reasons: %d", len(lan.reasons))
	}
	lan.WiFi(at, "wlan0: AP-STA-DISCONNECTED aa:bb:cc:dd:ee:01")
	lan.WiFi(at, fmt.Sprintf("wlan%d: AP-STA-DISCONNECTED aa:bb:cc:dd:ee:01", lanStateLimit))
	got := messages(l, WiFi)
	if strings.Contains(got[len(got)-2], "долго не отвечал") || !strings.Contains(got[len(got)-1], "долго не отвечал") {
		t.Fatal(got)
	}
}

func BenchmarkWiFiReasonEvents(b *testing.B) {
	for _, n := range []int{16, 4096} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			reasons, events := make([]string, n), make([]string, n)
			for i := 0; i < n; i++ {
				addr := fmt.Sprintf("02:00:00:00:%02x:%02x", i/256, i%256)
				reasons[i] = "wlan0: STA " + addr + " IEEE 802.11: deauthenticated due to inactivity"
				events[i] = "wlan0: AP-STA-DISCONNECTED " + addr
			}
			at := time.Unix(1000, 0)
			b.ReportAllocs()
			for b.Loop() {
				lan := &LAN{Log: New()}
				for _, line := range reasons {
					lan.WiFi(at, line)
				}
				for _, line := range events {
					lan.WiFi(at.Add(time.Second), line)
				}
			}
		})
	}
}
