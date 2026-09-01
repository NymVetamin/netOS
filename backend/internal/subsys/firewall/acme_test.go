package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestACMEOpensOnlyHTTPChallengePort(t *testing.T) {
	cfg := config.Default()
	cfg.System.Panel.TLS = config.TLS{Mode: "acme", Domain: "router.acme-valid.com", AcceptTOS: true}
	rules, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := `-A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m comment --comment "ACME HTTP-01" -j ACCEPT`
	if !strings.Contains(rules.IPv4, want) {
		t.Fatalf("ACME challenge rule absent:\n%s", rules.IPv4)
	}
	cfg.System.Panel.TLS = config.TLS{Mode: "selfsigned"}
	rules, err = Build(cfg)
	if err != nil || strings.Contains(rules.IPv4, "ACME HTTP-01") {
		t.Fatalf("ACME rule survived mode disable: err=%v\n%s", err, rules.IPv4)
	}
}
