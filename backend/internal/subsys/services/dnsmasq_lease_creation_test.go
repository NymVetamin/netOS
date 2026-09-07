package services

import (
	"context"
	"os"
	"runtime"
	"testing"
)

func TestDnsmasqCreatesPrivateLeaseFileBeforeFirstStart(t *testing.T) {
	useProviderPaths(t)
	cfg := providerTestConfig()
	cfg.DHCP.Enabled, cfg.DHCP.Provider = true, "dnsmasq"
	d := NewDnsmasq(newProviderRunner())
	if err := d.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dnsmasqLeasePath)
	if err != nil {
		t.Fatalf("private lease file must exist before dnsmasq starts: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("lease permissions = %o, want 600", info.Mode().Perm())
	}
	lease := []byte("2000000000 02:00:00:00:00:01 192.168.50.100 client *\n")
	if err := os.WriteFile(dnsmasqLeasePath, lease, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dnsmasqLeasePath)
	if err != nil || string(got) != string(lease) {
		t.Fatalf("repeat Apply lost existing leases: %q, %v", got, err)
	}
}
