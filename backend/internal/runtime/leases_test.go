package runtime

import (
	"os"
	"testing"
	"time"
)

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
	f := leaseFile(t, "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n192.168.1.21,AA:BB:CC:DD:EE:01,,3600,1787065200,1,0,0,laptop,0\n")
	defer f.Close()
	got, err := parseKeaLeases(f)
	if err != nil || len(got) != 1 {
		t.Fatalf("leases=%v err=%v", got, err)
	}
	if got[0].MAC != "aa:bb:cc:dd:ee:01" || got[0].Hostname != "laptop" {
		t.Fatalf("неверная аренда: %+v", got[0])
	}
}
