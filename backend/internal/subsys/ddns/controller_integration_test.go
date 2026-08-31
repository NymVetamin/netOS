//go:build linux

package ddns

import (
	"context"
	"os"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestIntegrationAddressFromInterface(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" {
		t.Skip("NETOS_INTEGRATION=1 is required")
	}
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "loopback-qa", Name: "lo", Type: "physical", Enabled: true}}
	cfg.WANs = []config.WAN{{ID: "wan-qa", Interface: "loopback-qa", Enabled: true, Proto: "static"}}
	cfg.DDNS = config.DDNS{Enabled: true, Provider: "duckdns", Hostname: "qa.duckdns.org", AddressSource: "interface", WAN: "wan-qa", Interval: 60, Token: "test"}
	address, err := New(nil).resolveAddress(context.Background(), cfg)
	if err != nil || address != "127.0.0.1" {
		t.Fatalf("loopback address = %q, err=%v", address, err)
	}
}
