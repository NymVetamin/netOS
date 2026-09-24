package services

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestRouterHostnameFollowsConfiguredLocalDomain(t *testing.T) {
	cfg := config.Default()
	cfg.System.Hostname = "qa-router"
	cfg.DNS.Enabled = true
	cfg.DNS.Provider = "dnsmasq"
	cfg.DNS.LocalDomain = "lan"
	cfg.Networks = []config.Network{{ID: "lan", Enabled: true, RouterAddress: "192.0.2.1/24"}}
	got := NewDnsmasq(nil).Render(cfg)
	if !strings.Contains(got, "host-record=qa-router.lan,192.0.2.1") {
		t.Fatalf("router hostname missing from local DNS")
	}
	cfg.System.Hostname = "renamed"
	got = NewDnsmasq(nil).Render(cfg)
	if strings.Contains(got, "host-record=qa-router.lan") || !strings.Contains(got, "host-record=renamed.lan,192.0.2.1") {
		t.Fatal("router hostname did not change with system setting")
	}
}
