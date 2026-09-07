//go:build linux

package firewall

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// Run inside an isolated network namespace: this test owns its bridge filter.
func TestIntegrationBridgeIPv6Suppression(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root in isolated network namespace")
	}
	r := system.NewExec()
	ctx := context.Background()
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := r.Run(ctx, name, args...)
		if err != nil {
			t.Fatalf("%s %v: %v", name, args, err)
		}
		return out
	}
	run("ip", "link", "add", "b6qa", "type", "bridge")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "b6qa").Run() })
	run("ip", "link", "set", "b6qa", "up")
	names := []string{fmt.Sprintf("b6qa-%d-l", os.Getpid()), fmt.Sprintf("b6qa-%d-r", os.Getpid())}
	for i, ns := range names {
		run("ip", "netns", "add", ns)
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
		port, peer := fmt.Sprintf("b6p%d", i), fmt.Sprintf("b6c%d", i)
		run("ip", "link", "add", port, "type", "veth", "peer", "name", peer)
		run("ip", "link", "set", peer, "netns", ns)
		run("ip", "link", "set", port, "master", "b6qa")
		run("ip", "link", "set", port, "up")
		run("ip", "netns", "exec", ns, "ip", "link", "set", peer, "up")
		run("ip", "netns", "exec", ns, "ip", "-6", "addr", "add", fmt.Sprintf("fd91:13::%d/64", i+1), "dev", peer, "nodad")
		run("ip", "netns", "exec", ns, "ip", "addr", "add", fmt.Sprintf("192.0.2.%d/24", i+1), "dev", peer)
	}
	ping := func(ip string, success bool) {
		t.Helper()
		out, err := r.Run(ctx, "ip", "netns", "exec", names[0], "ping", "-n", "-c", "1", "-W", "1", ip)
		if (err == nil) != success {
			t.Fatalf("ping %s success=%v, expected %v: %s %v", ip, err == nil, success, out, err)
		}
	}
	// Even with the host IPv6 stack disabled, the original implementation
	// forwards IPv6 between peers. These ACCEPT rules also exercise precedence.
	run("sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1")
	run("ebtables", "-A", "FORWARD", "-p", "IPv4", "-j", "ACCEPT")
	run("ebtables", "-A", "FORWARD", "-p", "IPv6", "-j", "ACCEPT")
	before := run("ebtables-save")
	ping("fd91:13::2", true)
	ping("192.0.2.2", true)
	cfg := config.Default()
	s := NewBridgeIPv6(r)
	for range 2 {
		if err := s.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if err := s.Health(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		ping("fd91:13::2", false)
		ping("192.0.2.2", true)
	}
	run("ebtables", "-I", "FORWARD", "1", "-p", "IPv6", "-j", "ACCEPT")
	run("ebtables", "-A", "FORWARD", "-p", "IPv6", "-j", bridgeIPv6Chain)
	if err := s.Health(ctx, cfg); err == nil {
		t.Fatal("health ignored a bypass and duplicate hook")
	}
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	ping("fd91:13::2", false)
	// Remove only the extra foreign fixture rule; the original ones remain.
	run("ebtables", "-D", "FORWARD", "-p", "IPv6", "-j", "ACCEPT")
	cfg.IPv6.Mode = "passthrough"
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	ping("fd91:13::2", true)
	ping("192.0.2.2", true)
	canonical := func(text string) string {
		var lines []string
		for _, line := range strings.Split(text, "\n") {
			if !strings.HasPrefix(line, "#") && line != "" {
				lines = append(lines, line)
			}
		}
		return strings.Join(lines, "\n")
	}
	if after := run("ebtables-save"); canonical(after) != canonical(before) {
		t.Fatalf("cleanup changed foreign rules:\nbefore=%s\nafter=%s", before, after)
	}
	if err := ClearBridgeIPv6(ctx, r.Run); err != nil {
		t.Fatal(err)
	}
}
