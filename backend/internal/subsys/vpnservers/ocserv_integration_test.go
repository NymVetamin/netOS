//go:build linux

package vpnservers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/channels"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationOcservAndOpenConnect(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root are required")
	}
	for _, command := range []string{"ocserv", "ocpasswd", "openconnect", "ip", "ping"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("%s is not installed", command)
		}
	}
	ctx := context.Background()
	runner := system.NewExec()
	const namespace = "netos-oc998"
	if _, err := runner.Run(ctx, "ip", "netns", "list"); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(ctx, "ip", "netns", "add", namespace); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = runner.Run(context.Background(), "ip", "netns", "delete", namespace) })
	if _, err := runner.Run(ctx, "ip", "link", "add", "veth-oc998h", "type", "veth", "peer", "name", "veth-oc998c"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = runner.Run(context.Background(), "ip", "link", "delete", "veth-oc998h") })
	for _, args := range [][]string{
		{"link", "set", "veth-oc998c", "netns", namespace},
		{"addr", "add", "192.0.2.1/30", "dev", "veth-oc998h"},
		{"link", "set", "veth-oc998h", "up"},
		{"netns", "exec", namespace, "ip", "addr", "add", "192.0.2.2/30", "dev", "veth-oc998c"},
		{"netns", "exec", namespace, "ip", "link", "set", "veth-oc998c", "up"},
		{"netns", "exec", namespace, "ip", "link", "set", "lo", "up"},
	} {
		if _, err := runner.Run(ctx, "ip", args...); err != nil {
			t.Fatal(err)
		}
	}
	filterRules := [][]string{
		{"INPUT", "-i", "veth-oc998h", "-p", "tcp", "--dport", "14443", "-m", "comment", "--comment", "netos-ocserv-integration", "-j", "ACCEPT"},
		{"INPUT", "-i", "veth-oc998h", "-p", "udp", "--dport", "14443", "-m", "comment", "--comment", "netos-ocserv-integration", "-j", "ACCEPT"},
		{"INPUT", "-i", "vpns998", "-p", "icmp", "-m", "comment", "--comment", "netos-ocserv-integration", "-j", "ACCEPT"},
	}
	for _, rule := range filterRules {
		args := append([]string{"-I", rule[0], "1"}, rule[1:]...)
		if _, err := runner.Run(ctx, "iptables", args...); err != nil {
			t.Fatal(err)
		}
		deleteArgs := append([]string{"-D", rule[0]}, rule[1:]...)
		t.Cleanup(func() { _, _ = runner.Run(context.Background(), "iptables", deleteArgs...) })
	}

	root, err := os.MkdirTemp("/var/lib", "netos-ocserv-integration-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	s := New(runner, root)
	server := config.VPNServer{
		ID: "integration-ocserv", Index: 998, Name: "Integration OpenConnect", Enabled: true, Type: "ocserv",
		Subnet: "10.98.0.1/24", Port: 14443, DefaultChannel: "direct",
		Config: map[string]any{"public_endpoint": "192.0.2.1:14443", "dns": []string{"10.98.0.1"}, "mtu": 1380},
		Peers:  []config.VPNPeer{{ID: "client", Name: "Client", Enabled: true, Address: "10.98.0.2", Credentials: map[string]string{"username": "integration", "password": "integration-secret"}}},
	}
	cfg := config.Default()
	cfg.System.Hostname = "netos-integration"
	cfg.Components = []config.Component{{ID: "ocserv", Installed: true}}
	cfg.VPNServers = []config.VPNServer{server}
	t.Cleanup(func() { _ = s.Apply(context.Background(), config.Default()) })
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	startedBefore, err := runner.Run(ctx, "systemctl", "show", "-p", "ActiveEnterTimestampMonotonic", "--value", "netos-ocserv-srv998.service")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	startedAfter, err := runner.Run(ctx, "systemctl", "show", "-p", "ActiveEnterTimestampMonotonic", "--value", "netos-ocserv-srv998.service")
	if err != nil || startedAfter != startedBefore {
		t.Fatalf("idempotent apply restarted ocserv: before=%q after=%q err=%v", startedBefore, startedAfter, err)
	}
	certPEM, err := os.ReadFile(filepath.Join(root, "ocserv-srv998-tls", "panel.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("invalid server certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pinSum := sha256.Sum256(spki)
	pin := "pin-sha256:" + base64.StdEncoding.EncodeToString(pinSum[:])
	var clientLog bytes.Buffer
	client := exec.Command("ip", "netns", "exec", namespace, "openconnect", "--verbose", "--non-inter", "--protocol=anyconnect", "--interface=tun-oc998", "--user=integration", "--passwd-on-stdin", "--servercert="+pin, "https://192.0.2.1:14443")
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
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := runner.Run(ctx, "ip", "netns", "exec", namespace, "ip", "-o", "-4", "addr", "show", "dev", "tun-oc998")
		if strings.Contains(out, "10.98.0.2") {
			ready = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("OpenConnect client did not receive its explicit address: %s", clientLog.String())
	}
	if out, err := runner.Run(ctx, "ip", "netns", "exec", namespace, "ping", "-c", "2", "-W", "2", "10.98.0.1"); err != nil || !strings.Contains(out, "2 received") {
		t.Fatalf("traffic did not cross the OpenConnect tunnel: %q (%v); client=%s", out, err, clientLog.String())
	}
	_ = client.Process.Kill()
	_, _ = client.Process.Wait()

	// Repeat the same real handshake through the netOS outbound-channel
	// lifecycle, not just the openconnect executable. This verifies the
	// generated protected unit, expected interface name and policy table.
	channelRoot, err := os.MkdirTemp("/var/lib", "netos-openconnect-channel-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(channelRoot) })
	channelSubsystem := channels.New(runner, channelRoot)
	channelSubsystem.RTTablesPath = filepath.Join(channelRoot, "rt_tables")
	channel := config.Channel{
		ID: "integration-openconnect", Index: 997, Name: "Integration OpenConnect",
		Enabled: true, Type: "openconnect", Mode: "tun", FailMode: "block",
		Config: map[string]any{
			"server": "https://192.0.2.1:14443", "username": "integration",
			"password": "integration-secret", "protocol": "anyconnect",
			"servercert": pin, "no_system_trust": true, "mtu": 1380,
		},
	}
	channelCfg := config.Default()
	channelCfg.Components = []config.Component{{ID: "openconnect", Installed: true}}
	channelCfg.Channels = append(channelCfg.Channels, channel)
	t.Cleanup(func() { _ = channelSubsystem.Apply(context.Background(), config.Default()) })
	if err := channelSubsystem.Apply(ctx, channelCfg); err != nil {
		t.Fatal(err)
	}
	if err := channelSubsystem.Health(ctx, channelCfg); err != nil {
		t.Fatal(err)
	}
	channelAddress, err := runner.Run(ctx, "ip", "-o", "-4", "addr", "show", "dev", "tun-ch997")
	if err != nil || !strings.Contains(channelAddress, "10.98.0.2") {
		t.Fatalf("netOS OpenConnect channel did not receive its address: %q (%v)", channelAddress, err)
	}
	if err := channelSubsystem.Apply(ctx, config.Default()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/etc/systemd/system/netos-openconnect-ch997.service"); !os.IsNotExist(err) {
		t.Fatalf("OpenConnect channel unit was not removed: %v", err)
	}

	if err := s.Apply(ctx, config.Default()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join("/etc/systemd/system", "netos-ocserv-srv998.service")); !os.IsNotExist(err) {
		t.Fatalf("ocserv unit was not removed: %v", err)
	}
}
