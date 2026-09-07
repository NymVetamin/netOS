//go:build linux

package netiface

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationDHCPClientLifecycleAndAddressOwnership(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root are required")
	}
	for _, command := range []string{"ip", "dnsmasq", "busybox", "iptables", "systemctl"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("%s is not installed", command)
		}
	}
	const (
		namespace = "netos-dhcpqa"
		clientIf  = "dhcpqa-host"
		serverIf  = "dhcpqa-srv"
		foreign   = "198.18.0.1/32"
	)
	ctx := context.Background()
	runner := system.NewExec()
	unit := "netos-dhcp-" + clientIf + ".service"
	unitPath := filepath.Join(systemdUnitDir, unit)
	scriptPath := filepath.Join(dhcpScriptDir, "udhcpc-"+clientIf+".sh")
	statePath := filepath.Join(dhcpRuntimeDir, "netos-dhcp-"+clientIf+".address")
	for _, path := range []string{unitPath, scriptPath, statePath} {
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("refusing to reuse existing integration artifact %s", path)
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	cleanup := func() {
		_, _ = runner.Run(context.Background(), "systemctl", "disable", "--now", unit)
		_ = os.Remove(unitPath)
		_ = os.Remove(scriptPath)
		_ = os.Remove(statePath)
		_, _ = runner.Run(context.Background(), "systemctl", "daemon-reload")
		_, _ = runner.Run(context.Background(), "iptables", "-D", "INPUT", "-i", clientIf, "-p", "udp", "--sport", "67", "--dport", "68", "-m", "comment", "--comment", "netos-dhcp-integration", "-j", "ACCEPT")
		_, _ = runner.Run(context.Background(), "ip", "netns", "delete", namespace)
		_, _ = runner.Run(context.Background(), "ip", "link", "delete", clientIf)
		_ = os.Remove("/tmp/netos-dhcpqa.leases")
	}
	cleanup()
	t.Cleanup(cleanup)

	mustRunVPNStyle(t, runner, "ip", "netns", "add", namespace)
	mustRunVPNStyle(t, runner, "ip", "link", "add", clientIf, "type", "veth", "peer", "name", serverIf)
	mustRunVPNStyle(t, runner, "ip", "link", "set", serverIf, "netns", namespace)
	mustRunVPNStyle(t, runner, "ip", "addr", "add", foreign, "dev", clientIf)
	mustRunVPNStyle(t, runner, "ip", "link", "set", clientIf, "up")
	mustRunVPNStyle(t, runner, "ip", "netns", "exec", namespace, "ip", "addr", "add", "192.0.2.1/24", "dev", serverIf)
	mustRunVPNStyle(t, runner, "ip", "netns", "exec", namespace, "ip", "link", "set", serverIf, "up")
	mustRunVPNStyle(t, runner, "ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up")
	mustRunVPNStyle(t, runner, "iptables", "-I", "INPUT", "1", "-i", clientIf, "-p", "udp", "--sport", "67", "--dport", "68", "-m", "comment", "--comment", "netos-dhcp-integration", "-j", "ACCEPT")

	dnsmasq := exec.Command("ip", "netns", "exec", namespace, "dnsmasq", "--no-daemon", "--conf-file=", "--port=0", "--interface="+serverIf, "--bind-interfaces", "--dhcp-range=192.0.2.100,192.0.2.110,255.255.255.0,2m", "--dhcp-option=3,192.0.2.1", "--dhcp-leasefile=/tmp/netos-dhcpqa.leases", "--user=root")
	var dnsmasqLog strings.Builder
	dnsmasq.Stdout, dnsmasq.Stderr = &dnsmasqLog, &dnsmasqLog
	if err := dnsmasq.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = dnsmasq.Process.Kill()
		_, _ = dnsmasq.Process.Wait()
	})
	time.Sleep(300 * time.Millisecond)

	s := NewWAN(runner)
	s.DHCPTimeout, s.DHCPPoll = 20*time.Second, 100*time.Millisecond
	w := config.WAN{ID: "dhcpqa", Name: "DHCP integration", Interface: "if-dhcpqa", Enabled: true, Proto: "dhcp", Metric: 4200}
	if err := s.ensureDHCPClient(ctx, w, clientIf); err != nil {
		t.Fatalf("start DHCP client: %v; dnsmasq=%s", err, dnsmasqLog.String())
	}
	if err := s.waitDHCP(ctx, clientIf, w.Name); err != nil {
		t.Fatalf("wait DHCP lease: %v; dnsmasq=%s", err, dnsmasqLog.String())
	}
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "if-dhcpqa", Name: clientIf, Type: "physical", Enabled: true}}
	cfg.WANs = []config.WAN{w}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	assertAddressPresent(t, runner, clientIf, foreign)

	w.Metric = 4201
	cfg.WANs[0] = w
	if err := s.ensureDHCPClient(ctx, w, clientIf); err != nil {
		t.Fatal(err)
	}
	if err := s.waitDHCP(ctx, clientIf, w.Name); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	assertAddressPresent(t, runner, clientIf, foreign)

	if err := s.stopDHCPClient(ctx, clientIf); err != nil {
		t.Fatal(err)
	}
	assertAddressPresent(t, runner, clientIf, foreign)
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("DHCP state remains after stop: %v", err)
	}
}

func mustRunVPNStyle(t *testing.T, runner system.Runner, name string, args ...string) {
	t.Helper()
	if out, err := runner.Run(context.Background(), name, args...); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

func TestIntegrationDHCPRenewWithoutRouterRemovesOnlyOwnedDefault(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root are required")
	}
	for _, command := range []string{"ip", "sh", "logger"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("%s is not installed", command)
		}
	}
	const namespace = "netos-dhcp-renewqa"
	const iface = "dhcpqa0"
	runner := system.NewExec()
	// An existing namespace belongs to somebody else; never remove it.
	if _, err := os.Stat("/run/netns/" + namespace); err == nil {
		t.Fatal("integration namespace already exists")
	}
	mustRunVPNStyle(t, runner, "ip", "netns", "add", namespace)
	t.Cleanup(func() { _, _ = runner.Run(context.Background(), "ip", "netns", "delete", namespace) })
	ns := func(args ...string) {
		t.Helper()
		mustRunVPNStyle(t, runner, "ip", append([]string{"-n", namespace}, args...)...)
	}
	ns("link", "add", iface, "type", "dummy")
	ns("link", "set", iface, "up")
	ns("addr", "add", "192.0.2.2/24", "dev", iface)
	ns("route", "add", "default", "via", "192.0.2.1", "dev", iface, "proto", "static", "metric", "99")
	ns("route", "add", "default", "via", "192.0.2.1", "dev", iface, "proto", "dhcp", "metric", "4200")
	root := t.TempDir()
	oldRuntime := dhcpRuntimeDir
	dhcpRuntimeDir = root
	t.Cleanup(func() { dhcpRuntimeDir = oldRuntime })
	script := filepath.Join(root, "renew.sh")
	if err := os.WriteFile(script, []byte(renderDHCPScript(4200)), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, gateway := range []string{"", "192.0.2.1", ""} {
		mustRunVPNStyle(t, runner, "ip", "netns", "exec", namespace, "env", "interface="+iface,
			"ip=192.0.2.2", "mask=24", "router="+gateway, "sh", script, "renew")
		routes, err := runner.Run(context.Background(), "ip", "-n", namespace, "-4", "route", "show", "default")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(routes, "proto static metric 99") {
			t.Fatalf("foreign default disappeared: %s", routes)
		}
		if strings.Contains(routes, "proto dhcp metric 4200") != (gateway != "") {
			t.Fatalf("renew gateway=%q left wrong DHCP default: %s", gateway, routes)
		}
		addresses, err := runner.Run(context.Background(), "ip", "-n", namespace, "-4", "addr", "show", "dev", iface)
		if err != nil || !strings.Contains(addresses, "192.0.2.2/24") {
			t.Fatalf("renew lost the leased address: %s, %v", addresses, err)
		}
	}
}

func TestIntegrationL2TPGatewayIgnoresStaleStaticRoute(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip is not installed")
	}
	const namespace = "netos-l2tp-gwqa"
	const iface = "wanqa0"
	if _, err := os.Stat("/run/netns/" + namespace); err == nil {
		t.Fatal("integration namespace already exists")
	}
	runner := system.NewExec()
	mustRunVPNStyle(t, runner, "ip", "netns", "add", namespace)
	t.Cleanup(func() { _, _ = runner.Run(context.Background(), "ip", "netns", "delete", namespace) })
	ns := func(args ...string) {
		t.Helper()
		mustRunVPNStyle(t, runner, "ip", append([]string{"-n", namespace}, args...)...)
	}
	ns("link", "add", iface, "type", "dummy")
	ns("link", "set", iface, "up")
	ns("addr", "add", "192.0.2.2/24", "dev", iface)
	ns("route", "add", "default", "via", "192.0.2.1", "dev", iface, "proto", "static", "metric", "100")
	s := NewWAN(netifaceRunnerFunc(func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "ip" {
			args = append([]string{"-n", namespace}, args...)
		}
		return runner.Run(ctx, name, args...)
	}))
	if gateway, err := s.underlayGateway(context.Background(), iface); err != nil || gateway != "" {
		t.Fatalf("old static route mistaken for DHCP lease: gateway=%q err=%v", gateway, err)
	}
	// The old, more-preferred static default can coexist until Apply cleanup.
	ns("route", "add", "default", "via", "192.0.2.254", "dev", iface, "proto", "dhcp", "metric", "310")
	if gateway, err := s.waitUnderlayGateway(context.Background(), iface); err != nil || gateway != "192.0.2.254" {
		t.Fatalf("wrong DHCP underlay gateway: gateway=%q err=%v", gateway, err)
	}
}

func assertAddressPresent(t *testing.T, runner system.Runner, iface, address string) {
	t.Helper()
	addresses, err := addressesOf(context.Background(), runner, iface)
	if err != nil || !addresses[address] {
		t.Fatalf("address %s missing on %s: %#v (%v)", address, iface, addresses, err)
	}
}
