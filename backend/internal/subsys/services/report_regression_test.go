package services

import (
	"github.com/netos-router/netos/internal/config"
	"strings"
	"testing"
)

func TestReportSplitTestOverridesBuiltInZone(t *testing.T) {
	cfg := config.Default()
	cfg.DHCP.Enabled = false
	cfg.DNS.Upstreams = []config.Upstream{{ID: "peer", Enabled: true, Type: "plain", Address: "198.51.100.1"}}
	cfg.DNS.SplitRules = []config.DNSSplitRule{{ID: "split", Enabled: true, Upstream: "peer", Domains: []string{"qa.test"}}}
	out := NewUnbound(nil).Render(cfg)
	if !strings.Contains(out, `local-zone: "qa.test." transparent`) {
		t.Fatal("split hidden by builtin .test zone")
	}
}
