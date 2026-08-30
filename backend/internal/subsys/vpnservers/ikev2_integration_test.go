//go:build linux

package vpnservers

import (
	"bytes"
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

func TestIntegrationIKEv2EAPAndXFRM(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root are required")
	}
	for _, command := range []string{"charon-systemd", "charon-cmd", "swanctl", "ip", "ping"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("%s is not installed", command)
		}
	}
	ctx := context.Background()
	runner := system.NewExec()
	// Installing Debian's strongSwan packages starts the distro service, while
	// netOS normally disables it in the component phase before this subsystem
	// runs. Model that phase here and restore a pre-existing service afterwards.
	stockActive := false
	if out, err := runner.Run(ctx, "systemctl", "is-active", "strongswan.service"); err == nil && strings.TrimSpace(out) == "active" {
		stockActive = true
		if _, err := runner.Run(ctx, "systemctl", "stop", "strongswan.service"); err != nil {
			t.Fatal(err)
		}
	}
	if stockActive {
		t.Cleanup(func() { _, _ = runner.Run(context.Background(), "systemctl", "start", "strongswan.service") })
	}
	const namespace = "netos-ike997"
	if _, err := runner.Run(ctx, "ip", "netns", "add", namespace); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = runner.Run(context.Background(), "ip", "netns", "delete", namespace) })
	if _, err := runner.Run(ctx, "ip", "link", "add", "veth-ike997h", "type", "veth", "peer", "name", "veth-ike997c"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = runner.Run(context.Background(), "ip", "link", "delete", "veth-ike997h") })
	for _, args := range [][]string{
		{"link", "set", "veth-ike997c", "netns", namespace},
		{"addr", "add", "192.0.2.1/30", "dev", "veth-ike997h"},
		{"link", "set", "veth-ike997h", "up"},
		{"netns", "exec", namespace, "ip", "addr", "add", "192.0.2.2/30", "dev", "veth-ike997c"},
		{"netns", "exec", namespace, "ip", "link", "set", "veth-ike997c", "up"},
		{"netns", "exec", namespace, "ip", "link", "set", "lo", "up"},
	} {
		if _, err := runner.Run(ctx, "ip", args...); err != nil {
			t.Fatal(err)
		}
	}
	filterRules := [][]string{
		{"INPUT", "-i", "veth-ike997h", "-p", "esp", "-m", "comment", "--comment", "netos-ikev2-integration", "-j", "ACCEPT"},
		{"INPUT", "-i", "veth-ike997h", "-p", "udp", "--dport", "500", "-m", "comment", "--comment", "netos-ikev2-integration", "-j", "ACCEPT"},
		{"INPUT", "-i", "veth-ike997h", "-p", "udp", "--dport", "4500", "-m", "comment", "--comment", "netos-ikev2-integration", "-j", "ACCEPT"},
		{"INPUT", "-i", "xfrm-srv997", "-p", "icmp", "-m", "comment", "--comment", "netos-ikev2-integration", "-j", "ACCEPT"},
	}
	for _, rule := range filterRules {
		args := append([]string{"-I", rule[0], "1"}, rule[1:]...)
		if _, err := runner.Run(ctx, "iptables", args...); err != nil {
			t.Fatal(err)
		}
		deleteArgs := append([]string{"-D", rule[0]}, rule[1:]...)
		t.Cleanup(func() { _, _ = runner.Run(context.Background(), "iptables", deleteArgs...) })
	}

	root, err := os.MkdirTemp("/var/lib", "netos-ikev2-integration-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	s := New(runner, root)
	server := config.VPNServer{
		ID: "integration-ikev2", Index: 997, Name: "Integration IKEv2", Enabled: true, Type: "ikev2",
		Subnet: "10.97.0.1/24", Port: 500, DefaultChannel: "direct",
		Config: map[string]any{"public_endpoint": "192.0.2.1", "server_identity": "netos-ikev2-integration", "dns": []string{"10.97.0.1"}, "mtu": 1400},
		Peers:  []config.VPNPeer{{ID: "client", Name: "Client", Enabled: true, Address: "10.97.0.2", Credentials: map[string]string{"username": "integration", "password": "integration-secret"}}},
	}
	cfg := config.Default()
	cfg.System.Hostname = "netos-ikev2-integration"
	cfg.Components = []config.Component{{ID: "strongswan", Installed: true}}
	cfg.VPNServers = []config.VPNServer{server}
	t.Cleanup(func() { _ = s.Apply(context.Background(), config.Default()) })
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	startedBefore, err := runner.Run(ctx, "systemctl", "show", "-p", "ActiveEnterTimestampMonotonic", "--value", ikev2Unit)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	startedAfter, err := runner.Run(ctx, "systemctl", "show", "-p", "ActiveEnterTimestampMonotonic", "--value", ikev2Unit)
	if err != nil || startedAfter != startedBefore {
		t.Fatalf("idempotent apply restarted strongSwan: before=%q after=%q err=%v", startedBefore, startedAfter, err)
	}

	cert := filepath.Join(root, "strongswan", "x509", "server.crt")
	var clientLog bytes.Buffer
	client := exec.Command("ip", "netns", "exec", namespace, "charon-cmd",
		"--host", "192.0.2.1", "--identity", "integration", "--eap-identity", "integration",
		"--remote-identity", "netos-ikev2-integration", "--cert", cert, "--profile", "ikev2-eap",
		"--ike-proposal", "aes256gcm16-prfsha384-ecp384", "--esp-proposal", "aes256gcm16-ecp384", "--debug", "1")
	client.Stdin = strings.NewReader("integration-secret\n")
	client.Stdout, client.Stderr = &clientLog, &clientLog
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Process.Kill()
		_, _ = client.Process.Wait()
	})
	ready := false
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := runner.Run(ctx, "ip", "netns", "exec", namespace, "ip", "-o", "-4", "addr", "show")
		if strings.Contains(out, "10.97.0.2") {
			ready = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("IKEv2 client did not receive its address: %s", clientLog.String())
	}
	if out, err := runner.Run(ctx, "ip", "netns", "exec", namespace, "ping", "-c", "2", "-W", "2", "10.97.0.1"); err != nil || !strings.Contains(out, "2 received") {
		links, _ := runner.Run(ctx, "ip", "-s", "link", "show", "xfrm-srv997")
		states, _ := runner.Run(ctx, "ip", "-s", "xfrm", "state")
		policies, _ := runner.Run(ctx, "ip", "-s", "xfrm", "policy")
		clientRoutes, _ := runner.Run(ctx, "ip", "netns", "exec", namespace, "ip", "route", "show", "table", "all")
		clientStates, _ := runner.Run(ctx, "ip", "netns", "exec", namespace, "ip", "-s", "xfrm", "state")
		clientPolicies, _ := runner.Run(ctx, "ip", "netns", "exec", namespace, "ip", "-s", "xfrm", "policy")
		rules, _ := runner.Run(ctx, "iptables", "-nvL", "INPUT")
		t.Fatalf("traffic did not cross the IKEv2 tunnel: %q (%v); link=%s states=%s policies=%s input=%s client-routes=%s client-states=%s client-policies=%s client=%s", out, err, links, states, policies, rules, clientRoutes, clientStates, clientPolicies, clientLog.String())
	}
	_ = client.Process.Kill()
	_, _ = client.Process.Wait()
	if err := s.Apply(ctx, config.Default()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join("/etc/systemd/system", ikev2Unit)); !os.IsNotExist(err) {
		t.Fatalf("strongSwan unit was not removed: %v", err)
	}
}
