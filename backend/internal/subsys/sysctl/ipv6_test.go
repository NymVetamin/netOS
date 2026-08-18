package sysctl

import (
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestPassthroughRestoresIPv6Autoconfiguration(t *testing.T) {
	cfg := config.Default()
	cfg.IPv6.Mode = "passthrough"
	values := NewIPv6(nil).values(cfg)
	want := map[string]string{
		"net.ipv6.conf.all.disable_ipv6": "0",
		"net.ipv6.conf.all.accept_ra":    "1",
		"net.ipv6.conf.all.autoconf":     "1",
	}
	for key, value := range want {
		if values[key] != value {
			t.Fatalf("%s=%q, ожидалось %q", key, values[key], value)
		}
	}
}
