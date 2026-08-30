//go:build linux

package firewall

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestIntegrationIptablesAcceptsGeneratedRuleset(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" {
		t.Skip("интеграционный тест: NETOS_INTEGRATION=1 и root")
	}
	if os.Geteuid() != 0 {
		t.Skip("нужен root")
	}
	for _, bin := range []string{"iptables-restore", "ip6tables-restore"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("нет %s", bin)
		}
	}

	cfg := config.Default()
	cfg.Interfaces = []config.Interface{
		{ID: "lan-if", Name: "nftest-lan", Type: "physical", Enabled: true},
		{ID: "wan-if", Name: "nftest-wan", Type: "physical", Enabled: true},
		{ID: "wan2-if", Name: "nftest-wan2", Type: "physical", Enabled: true},
	}
	cfg.Networks = []config.Network{
		{ID: "lan", Name: "LAN", Interface: "lan-if", RouterAddress: "192.0.2.1/24", Zone: "lan", Enabled: true},
	}
	cfg.WANs = []config.WAN{
		{ID: "wan", Index: 1, Name: "WAN", Interface: "wan-if", Proto: "static", Address: "198.51.100.2/24", Gateway: "198.51.100.1", Metric: 100, Weight: 1, Enabled: true},
		{ID: "wan2", Index: 2, Name: "WAN2", Interface: "wan2-if", Proto: "static", Address: "203.0.113.2/24", Gateway: "203.0.113.1", Metric: 200, Weight: 2, Enabled: true},
	}
	cfg.MultiWAN.Enabled, cfg.MultiWAN.Mode = true, "balance"
	cfg.Clients = []config.Client{
		{ID: "blocked", Name: "Тестовый клиент", MAC: "02:00:00:00:00:01", Blocked: true},
	}
	cfg.Channels = append(cfg.Channels, config.Channel{
		ID: "wg-test", Index: 99, Name: "Тестовый VPN", Enabled: true, Type: "wireguard",
	})
	cfg.DNS.Upstreams[0].Channel = "wg-test"
	cfg.Policies = []config.Policy{{
		ID: "https-vpn", Name: "HTTPS через VPN", Enabled: true, Priority: 100,
		Channel: "wg-test", Protocol: "tcp", DstPort: "443,8000-8010",
	}}

	rules, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		bin   string
		input string
	}{
		{bin: "iptables-restore", input: rules.IPv4},
		{bin: "ip6tables-restore", input: rules.IPv6},
	} {
		cmd := exec.Command(check.bin, "--test")
		cmd.Stdin = bytes.NewBufferString(check.input)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s отверг сгенерированные правила: %v\n%s\n%s", check.bin, err, out, check.input)
		}
	}
}
