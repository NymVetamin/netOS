//go:build linux

package firewall

import (
	"context"
	"fmt"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestIntegrationPolicyBlock(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("root isolated namespace required")
	}
	self, _ := os.Readlink("/proc/self/ns/net")
	init, _ := os.Readlink("/proc/1/ns/net")
	if self == init {
		t.Fatal("refusing host namespace")
	}
	r := system.NewExec()
	ctx := context.Background()
	run := func(name string, args ...string) string {
		t.Helper()
		o, e := r.Run(ctx, name, args...)
		if e != nil {
			t.Fatalf("%s %v: %s %v", name, args, o, e)
		}
		return o
	}
	names := []string{fmt.Sprintf("nbc%d", os.Getpid()), fmt.Sprintf("nbd%d", os.Getpid())}
	for i, ns := range names {
		run("ip", "netns", "add", ns)
		t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
		dev := []string{"lan0", "dst0"}[i]
		run("ip", "link", "add", dev, "type", "veth", "peer", "name", "peer0")
		run("ip", "link", "set", "peer0", "netns", ns)
		subnet := []string{"192.0.2.", "10.22.0."}[i]
		run("ip", "addr", "add", subnet+"1/24", "dev", dev)
		run("ip", "link", "set", dev, "up")
		run("ip", "netns", "exec", ns, "ip", "addr", "add", subnet+"2/24", "dev", "peer0")
		run("ip", "netns", "exec", ns, "ip", "link", "set", "peer0", "up")
		run("ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", subnet+"1")
	}
	run("ip", "netns", "exec", names[0], "ip", "link", "set", "peer0", "address", "02:00:00:00:00:02")
	run("ip", "netns", "exec", names[1], "ip", "addr", "add", "198.51.100.2/32", "dev", "peer0")
	run("ip", "route", "add", "198.51.100.2/32", "via", "10.22.0.2")
	run("sysctl", "-w", "net.ipv4.ip_forward=1")
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "source", Name: "lan0"}, {ID: "inside", Name: "dst0"}}
	cfg.Networks = []config.Network{
		{ID: "source", Interface: "source", Zone: "lan", Enabled: true, RouterAddress: "192.0.2.1/24"},
		{ID: "local", Interface: "inside", Zone: "lan", Enabled: true, RouterAddress: "10.22.0.1/24"},
	}
	cfg.Firewall.Rules = append(cfg.Firewall.Rules, config.FirewallRule{ID: "internal", Enabled: true, Zone: "lan", Flow: "forward", DstIP: "10.22.0.0/24", Action: "accept"})
	cfg.Clients = []config.Client{{MAC: "02:00:00:00:00:02"}}
	apply := func() {
		t.Helper()
		var b builder
		b.mangle(cfg, buildZoneMap(cfg))
		b.filter(cfg, buildZoneMap(cfg))
		cmd := exec.Command("iptables-restore")
		cmd.Stdin = strings.NewReader(b.String())
		if o, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("restore: %s %v", o, e)
		}
	}
	ping := func(ip string, want bool) {
		t.Helper()
		o, e := r.Run(ctx, "ip", "netns", "exec", names[0], "ping", "-c", "1", "-W", "1", ip)
		if (e == nil) != want {
			t.Fatalf("ping %s expected %v: %s %v", ip, want, o, e)
		}
	}

	apply()
	ping("198.51.100.2", true)
	cfg.Policies = []config.Policy{{ID: "deny", Enabled: true, Priority: 20, Channel: config.InternetBlockChannel, SrcIP: "192.0.2.2", DstIP: "198.51.100.2", Protocol: "icmp"}}
	for i := 0; i < 2; i++ {
		apply()
		ping("198.51.100.2", false)
		ping("10.22.0.2", true)
		ping("192.0.2.1", true)
	}
	cfg.Policies[0].SrcIP = "192.0.2.3"
	apply()
	ping("198.51.100.2", true)
	cfg.Policies[0].SrcIP = "192.0.2.2"
	cfg.Policies = append(cfg.Policies, config.Policy{ID: "allow", Enabled: true, Priority: 10, Channel: "direct", DstIP: "198.51.100.2"})
	apply()
	ping("198.51.100.2", true)
	cfg.Policies = cfg.Policies[:1]
	cfg.Policies[0].Enabled = false
	apply()
	ping("198.51.100.2", true)
	cfg.Policies[0].Enabled = true
	cfg.Policies[0].DstIP = ""
	apply()
	ping("198.51.100.2", false)
	ping("10.22.0.2", false)
	ping("192.0.2.1", true)
	cfg.Policies = nil
	apply()
	ping("198.51.100.2", true)
	ping("10.22.0.2", true)
}
