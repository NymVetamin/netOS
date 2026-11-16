package eventlog

import (
	"strings"
	"testing"
	"time"
)

func lanFixture() (*Log, *LAN) {
	l := New()
	return l, &LAN{Log: l, Names: &Names{
		Client: func(mac string) string {
			if mac == "aa:bb:cc:dd:ee:01" {
				return "Телефон"
			}
			return ""
		},
		SSID: func(iface string) string {
			if iface == "wlan0" {
				return "Home"
			}
			return ""
		},
	}}
}

func TestWiFiEvents(t *testing.T) {
	l, lan := lanFixture()
	at := time.Unix(1792000000, 0)
	for i, line := range []string{
		"wlan0: STA aa:bb:cc:dd:ee:01 IEEE 802.11: authenticated",
		"wlan0: AP-STA-CONNECTED aa:bb:cc:dd:ee:01 auth_alg=open",
		"wlan0: STA aa:bb:cc:dd:ee:01 IEEE 802.11: disassociated due to inactivity",
		"wlan0: AP-STA-DISCONNECTED aa:bb:cc:dd:ee:01",
		"wlan0-n2: AP-STA-POSSIBLE-PSK-MISMATCH AA:BB:CC:DD:EE:02",
		"wlan0-n2: AP-STA-POSSIBLE-PSK-MISMATCH AA:BB:CC:DD:EE:02", // retry of the same attempt
		"wlan0: STA aa:bb:cc:dd:ee:01 IEEE 802.11: disassociated",
		"wlan0: AP-STA-DISCONNECTED aa:bb:cc:dd:ee:01",
	} {
		lan.WiFi(at.Add(time.Duration(i)*time.Second), line)
	}
	want := strings.Join([]string{
		"info Home: Телефон (aa:bb:cc:dd:ee:01) подключился",
		"info Home: Телефон (aa:bb:cc:dd:ee:01) отключился: долго не отвечал",
		"warning wlan0-n2: aa:bb:cc:dd:ee:02: неверный пароль Wi-Fi",
		"info Home: Телефон (aa:bb:cc:dd:ee:01) отключился",
	}, "\n")
	if got := strings.Join(messages(l, WiFi), "\n"); got != want {
		t.Fatalf("got:\n%s", got)
	}
}

func TestDHCPEventsAllServersWithoutRenewals(t *testing.T) {
	l, lan := lanFixture()
	at := time.Unix(1792000000, 0)
	for _, line := range []string{
		// dnsmasq (journal or dns.log)
		"Nov 16 10:00:00 dnsmasq-dhcp[1]: DHCPDISCOVER(br0) aa:bb:cc:dd:ee:01",
		"Nov 16 10:00:00 dnsmasq-dhcp[1]: DHCPOFFER(br0) 192.168.1.23 aa:bb:cc:dd:ee:01",
		"Nov 16 10:00:00 dnsmasq-dhcp[1]: DHCPACK(br0) 192.168.1.23 aa:bb:cc:dd:ee:01 phone",
		"DHCPACK(br0) 192.168.1.23 aa:bb:cc:dd:ee:01 phone", // renewal
		"DHCPACK(br0) 192.168.1.40 aa:bb:cc:dd:ee:03 laptop",
		"DHCPRELEASE(br0) 192.168.1.40 aa:bb:cc:dd:ee:03",
		"DHCPNAK(br0) 192.168.1.99 aa:bb:cc:dd:ee:04 wrong network",
		"DHCPDISCOVER(br0) aa:bb:cc:dd:ee:05 no address available",
		// ISC dhcpd
		"DHCPACK on 10.0.0.10 to aa:bb:cc:dd:ee:06 (printer) via br1",
		"DHCPACK on 10.0.0.10 to aa:bb:cc:dd:ee:06 (printer) via br1",
		"DHCPRELEASE of 10.0.0.10 from aa:bb:cc:dd:ee:06 (printer) via br1 (found)",
		"DHCPDISCOVER from aa:bb:cc:dd:ee:07 via br1: network 10.0.0.0/24: no free leases",
		// Kea
		"INFO  [kea-dhcp4.leases/123] DHCP4_LEASE_ALLOC [hwtype=1 aa:bb:cc:dd:ee:08], cid=[no info], tid=0x1: lease 10.1.0.5 has been allocated for 3600 seconds",
		"INFO  [kea-dhcp4.leases/123] DHCP4_LEASE_ALLOC [hwtype=1 aa:bb:cc:dd:ee:08], cid=[no info], tid=0x2: lease 10.1.0.5 has been allocated for 3600 seconds",
		"INFO  [kea-dhcp4.leases/123] DHCP4_RELEASE [hwtype=1 aa:bb:cc:dd:ee:08], cid=[no info], tid=0x3: address 10.1.0.5 was released properly.",
		"WARN  [kea-dhcp4.alloc-engine/123] ALLOC_ENGINE_V4_ALLOC_FAIL [hwtype=1 aa:bb:cc:dd:ee:09], cid=[no info], tid=0x4: failed to allocate an IPv4 address after 5 attempt(s)",
		"query[A] example.com from 192.168.1.5",
	} {
		lan.DHCP(at, line)
	}
	want := strings.Join([]string{
		"info DHCP br0: Телефон (aa:bb:cc:dd:ee:01) получил 192.168.1.23",
		"info DHCP br0: laptop (aa:bb:cc:dd:ee:03) получил 192.168.1.40",
		"info DHCP br0: laptop (aa:bb:cc:dd:ee:03) освободил 192.168.1.40",
		"warning DHCP br0: aa:bb:cc:dd:ee:04: отказ в адресе 192.168.1.99 (wrong network)",
		"error DHCP br0: aa:bb:cc:dd:ee:05: нет свободных адресов",
		"info DHCP br1: printer (aa:bb:cc:dd:ee:06) получил 10.0.0.10",
		"info DHCP br1: printer (aa:bb:cc:dd:ee:06) освободил 10.0.0.10",
		"error DHCP br1: aa:bb:cc:dd:ee:07: нет свободных адресов",
		"info DHCP: aa:bb:cc:dd:ee:08 получил 10.1.0.5",
		"info DHCP: aa:bb:cc:dd:ee:08 освободил 10.1.0.5",
		"error DHCP: aa:bb:cc:dd:ee:09: нет свободных адресов",
	}, "\n")
	if got := strings.Join(messages(l, DHCP), "\n"); got != want {
		t.Fatalf("got:\n%s", got)
	}
}

func TestLANStateIsBounded(t *testing.T) {
	_, lan := lanFixture()
	at := time.Unix(1792000000, 0)
	for i := 0; i < lanStateLimit+10; i++ {
		lan.DHCP(at, "DHCPACK(br0) 10.0.0.1 aa:bb:cc:"+string(rune('a'+i/4096%6))+"0:"+hex2(i/256)+":"+hex2(i%256))
	}
	if len(lan.leases) > lanStateLimit {
		t.Fatal(len(lan.leases))
	}
}

func hex2(n int) string {
	const d = "0123456789abcdef"
	return string([]byte{d[n/16%16], d[n%16]})
}
