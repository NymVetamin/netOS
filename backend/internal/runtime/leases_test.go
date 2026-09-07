package runtime

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestLeasePathForProvider(t *testing.T) {
	if got := leasePathForProvider("kea", "/dnsmasq.leases"); got != "/var/lib/kea/netos-leases4.csv" {
		t.Fatalf("Kea lease path = %q", got)
	}
	if got := leasePathForProvider("isc-dhcp-server", "/dnsmasq.leases"); got != "/var/lib/netos/dhcpd.leases" {
		t.Fatalf("ISC lease path = %q", got)
	}
	if got := leasePathForProvider("dnsmasq", "/dnsmasq.leases"); got != "/dnsmasq.leases" {
		t.Fatalf("dnsmasq lease path = %q", got)
	}
}

func leaseFile(t *testing.T, body string) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "leases-")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(body); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestParseISCLeases(t *testing.T) {
	f := leaseFile(t, "lease 192.168.1.20 {\n  ends 2 2026/08/18 15:00:00;\n  binding state active;\n  hardware ethernet AA:BB:CC:DD:EE:FF;\n  client-hostname \"phone\";\n}\n")
	defer f.Close()
	got, err := parseISCLeases(f)
	if err != nil || len(got) != 1 {
		t.Fatalf("leases=%v err=%v", got, err)
	}
	if got[0].MAC != "aa:bb:cc:dd:ee:ff" || got[0].Hostname != "phone" || got[0].Expires.Location() != time.UTC {
		t.Fatalf("неверная аренда: %+v", got[0])
	}
}

func TestParseKeaLeases(t *testing.T) {
	f := leaseFile(t, fmt.Sprintf("address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n192.168.1.21,AA:BB:CC:DD:EE:01,,3600,%d,1,0,0,laptop,0\n", time.Now().Add(time.Hour).Unix()))
	defer f.Close()
	got, err := parseKeaLeases(f)
	if err != nil || len(got) != 1 {
		t.Fatalf("leases=%v err=%v", got, err)
	}
	if got[0].MAC != "aa:bb:cc:dd:ee:01" || got[0].Hostname != "laptop" {
		t.Fatalf("неверная аренда: %+v", got[0])
	}
}

func TestParseKeaLeaseJournal(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	past := time.Now().Add(-time.Hour).Unix()
	row := func(mac string, lifetime, expiry int64, hostname, state string) string {
		return fmt.Sprintf("192.168.1.21,%s,,%d,%d,1,0,0,%s,%s\n", mac, lifetime, expiry, hostname, state)
	}
	active := row("aa:bb:cc:dd:ee:01", 3600, future, "old", "0")
	for _, tc := range []struct {
		name, journal, hostname string
		count                   int
	}{
		{"renewal", active + row("aa:bb:cc:dd:ee:02", 7200, future+3600, "new", "0"), "new", 1},
		{"release", active + row("aa:bb:cc:dd:ee:01", 0, past, "old", "0"), "", 0},
		{"release without MAC", active + row("", 0, past, "", "0"), "", 0},
		{"declined", active + row("aa:bb:cc:dd:ee:01", 3600, future, "old", "1"), "", 0},
		{"reclaimed", active + row("aa:bb:cc:dd:ee:01", 3600, future, "old", "2"), "", 0},
		{"expired latest supersedes future record", active + row("aa:bb:cc:dd:ee:01", 3600, past, "old", "0"), "", 0},
		{"reacquired after release", active + row("", 0, past, "", "0") + row("aa:bb:cc:dd:ee:02", 3600, future, "\"new, host\"", "0"), "new, host", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := leaseFile(t, "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n"+tc.journal)
			defer f.Close()
			got, err := parseKeaLeases(f)
			if err != nil || len(got) != tc.count {
				t.Fatalf("leases=%+v err=%v; want %d leases", got, err, tc.count)
			}
			if tc.count > 0 && (got[0].Hostname != tc.hostname || got[0].MAC != "aa:bb:cc:dd:ee:02") {
				t.Fatalf("latest lease not returned: %+v", got[0])
			}
		})
	}
}
