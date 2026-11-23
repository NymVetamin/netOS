package eventlog

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestWiFiPasswordFailuresBelongToInterface(t *testing.T) {
	log, lan := lanFixture()
	at := time.Unix(1000, 0)
	emit := func(offset int, iface, addr string) {
		lan.WiFi(at.Add(time.Duration(offset)*time.Second), iface+": AP-STA-POSSIBLE-PSK-MISMATCH "+addr)
	}
	emit(0, "wlan0", "AA:BB:CC:DD:EE:01")
	emit(1, "wlan1", "aa:bb:cc:dd:ee:01")
	if got := messages(log, WiFi); len(got) != 2 {
		t.Fatalf("second interface lost: %v", got)
	}
	emit(29, "wlan0", "aa:bb:cc:dd:ee:01")
	emit(30, "wlan1", "AA:BB:CC:DD:EE:01")
	if got := messages(log, WiFi); len(got) != 2 {
		t.Fatalf("retry not suppressed: %v", got)
	}
	emit(30, "wlan0", "aa:bb:cc:dd:ee:01")
	emit(31, "wlan1", "aa:bb:cc:dd:ee:01")
	emit(31, "wlan1", "aa:bb:cc:dd:ee:02")
	emit(31, "wlan1", "invalid")
	if got := messages(log, WiFi); len(got) != 5 {
		t.Fatalf("expiry/other client: %v", got)
	}
}

func TestWiFiPasswordFailureStateIsBounded(t *testing.T) {
	log, lan := lanFixture()
	at := time.Unix(1000, 0)
	for i := 0; i <= lanStateLimit; i++ {
		lan.WiFi(at, fmt.Sprintf("wlan%d: AP-STA-POSSIBLE-PSK-MISMATCH aa:bb:cc:dd:ee:01", i))
	}
	if len(lan.mismatch) > lanStateLimit {
		t.Fatal("unbounded password failure state")
	}
	if len(lan.mismatch) != 1 {
		t.Fatalf("overflow did not clear old entries: %d", len(lan.mismatch))
	}
	lan.WiFi(at, "wlan0: AP-STA-POSSIBLE-PSK-MISMATCH aa:bb:cc:dd:ee:01")
	got := messages(log, WiFi)
	if !strings.Contains(got[len(got)-1], "Home:") {
		t.Fatal("old key still suppressed after overflow", got[len(got)-1])
	}
}

func BenchmarkWiFiPasswordFailures(b *testing.B) {
	for _, n := range []int{16, 4096} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			lines := make([]string, n)
			for i := range lines {
				lines[i] = fmt.Sprintf("wlan0: AP-STA-POSSIBLE-PSK-MISMATCH 02:00:00:00:%02x:%02x", i/256, i%256)
			}
			at := time.Unix(1000, 0)
			b.ReportAllocs()
			for b.Loop() {
				lan := &LAN{Log: New()}
				for _, line := range lines {
					lan.WiFi(at, line)
				}
				for _, line := range lines {
					lan.WiFi(at.Add(time.Second), line)
				}
			}
		})
	}
}
