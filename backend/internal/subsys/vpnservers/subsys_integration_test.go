//go:build linux

package vpnservers

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationWireGuardServerHandshake(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root are required")
	}
	for _, bin := range []string{"ip", "wg", "ping", "iptables"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("нет %s", bin)
		}
	}
	ctx := context.Background()
	runner := system.NewExec()
	clientName := "wg-vpntest"
	netns := "netos-wgtest"
	hostVeth := "wgtest-host"
	clientVeth := "wgtest-peer"
	serverIndex := 997
	serverName := fmt.Sprintf("wg-srv%d", serverIndex)
	cleanup := func() {
		_, _ = runner.Run(ctx, "iptables", "-D", "INPUT", "-i", hostVeth, "-p", "udp", "--dport", "51997", "-j", "ACCEPT")
		_, _ = runner.Run(ctx, "iptables", "-D", "INPUT", "-i", serverName, "-p", "icmp", "-j", "ACCEPT")
		_, _ = runner.Run(ctx, "ip", "netns", "delete", netns)
		_, _ = runner.Run(ctx, "ip", "link", "delete", hostVeth)
		_, _ = runner.Run(ctx, "ip", "link", "delete", serverName)
	}
	cleanup()
	t.Cleanup(cleanup)

	serverPrivate, serverPublic := wgKeypair(t)
	clientPrivate, clientPublic := wgKeypair(t)
	root := t.TempDir()
	s := New(runner, root)
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "wireguard", Installed: true}}
	cfg.VPNServers = []config.VPNServer{{
		ID: "integration", Index: serverIndex, Name: "Integration WG server", Enabled: true, Type: "wireguard",
		Subnet: "10.253.97.1/24", Port: 51997, Config: map[string]any{"private_key": serverPrivate},
		Peers: []config.VPNPeer{{ID: "client", Name: "Integration client", Enabled: true, Address: "10.253.97.2", Credentials: map[string]string{"public_key": clientPublic}}},
	}}
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}

	clientConf := filepath.Join(root, "client.conf")
	body := fmt.Sprintf("[Interface]\nPrivateKey = %s\nListenPort = 51998\n\n[Peer]\nPublicKey = %s\nEndpoint = 192.0.2.1:51997\nAllowedIPs = 10.253.97.1/32\nPersistentKeepalive = 1\n", clientPrivate, serverPublic)
	if err := os.WriteFile(clientConf, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	mustRunVPN(t, runner, "ip", "netns", "add", netns)
	mustRunVPN(t, runner, "ip", "link", "add", hostVeth, "type", "veth", "peer", "name", clientVeth)
	mustRunVPN(t, runner, "ip", "link", "set", clientVeth, "netns", netns)
	mustRunVPN(t, runner, "ip", "addr", "add", "192.0.2.1/30", "dev", hostVeth)
	mustRunVPN(t, runner, "ip", "link", "set", hostVeth, "up")
	mustRunVPN(t, runner, "iptables", "-I", "INPUT", "1", "-i", hostVeth, "-p", "udp", "--dport", "51997", "-j", "ACCEPT")
	// In production the firewall subsystem permits traffic from an enabled VPN
	// server interface. This isolated subsystem test must model that rule itself.
	mustRunVPN(t, runner, "iptables", "-I", "INPUT", "1", "-i", serverName, "-p", "icmp", "-j", "ACCEPT")
	mustRunVPN(t, runner, "ip", "netns", "exec", netns, "ip", "link", "set", "lo", "up")
	mustRunVPN(t, runner, "ip", "netns", "exec", netns, "ip", "addr", "add", "192.0.2.2/30", "dev", clientVeth)
	mustRunVPN(t, runner, "ip", "netns", "exec", netns, "ip", "link", "set", clientVeth, "up")
	mustRunVPN(t, runner, "ip", "netns", "exec", netns, "ip", "link", "add", "name", clientName, "type", "wireguard")
	mustRunVPN(t, runner, "ip", "netns", "exec", netns, "wg", "syncconf", clientName, clientConf)
	mustRunVPN(t, runner, "ip", "netns", "exec", netns, "ip", "addr", "add", "10.253.97.2/32", "dev", clientName)
	mustRunVPN(t, runner, "ip", "netns", "exec", netns, "ip", "link", "set", "dev", clientName, "up")
	mustRunVPN(t, runner, "ip", "netns", "exec", netns, "ip", "route", "add", "10.253.97.1/32", "dev", clientName)
	mustRunVPN(t, runner, "ip", "netns", "exec", netns, "ping", "-c", "2", "-W", "2", "10.253.97.1")

	handshake, err := runner.Run(ctx, "wg", "show", serverName, "latest-handshakes")
	if err != nil || strings.HasSuffix(strings.TrimSpace(handshake), "\t0") || strings.TrimSpace(handshake) == "" {
		t.Fatalf("нет WireGuard handshake: %q (%v)", handshake, err)
	}
	next := *cfg
	next.VPNServers = append([]config.VPNServer(nil), cfg.VPNServers...)
	server := &next.VPNServers[0]
	server.Config = map[string]any{"private_key": serverPrivate, "public_endpoint": "vpn.example:51997", "client_dns": []string{"192.0.2.53"}, "client_allowed_ips": []string{"198.51.100.0/24"}}
	server.Peers = append([]config.VPNPeer(nil), server.Peers...)
	server.Peers[0].WireGuardProfile = &config.WireGuardClientProfile{UseRouterDNS: true, AllowedIPs: []string{"192.0.2.0/24"}}
	if actions, err := s.Plan(cfg, &next); err != nil || len(actions) != 0 {
		t.Fatalf("export-only plan: %v %v", actions, err)
	}
	for i := 0; i < 2; i++ {
		if err := s.Apply(ctx, &next); err != nil {
			t.Fatal(err)
		}
		if err := s.Health(ctx, &next); err != nil {
			t.Fatal(err)
		}
		mustRunVPN(t, runner, "ip", "netns", "exec", netns, "ping", "-c", "2", "-W", "2", "10.253.97.1")
		after, err := runner.Run(ctx, "wg", "show", serverName, "latest-handshakes")
		if err != nil || after != handshake {
			t.Fatalf("export edit reset handshake: %v", err)
		}
	}
	channelEdit := next
	rename := next
	rename.VPNServers = append([]config.VPNServer(nil), next.VPNServers...)
	rename.VPNServers[0].Name = "Renamed WireGuard"
	serverConf := filepath.Join(root, serverName+".conf")
	savedConf, err := os.ReadFile(serverConf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(serverConf, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	actions, planErr := s.Plan(&next, &rename)
	restoreErr := os.WriteFile(serverConf, savedConf, 0600)
	if planErr != nil || restoreErr != nil || len(actions) != 1 || !actions[0].Disruptive {
		t.Fatalf("rename hid runtime repair: %+v %v restore=%v", actions, planErr, restoreErr)
	}
	for _, pair := range [][2]*config.Config{{&next, &rename}, {&rename, &rename}, {&rename, &next}} {
		if actions, err := s.Plan(pair[0], pair[1]); err != nil || len(actions) != 0 {
			t.Fatalf("name-only plan: %v %v", actions, err)
		}
		if err := s.Apply(ctx, pair[1]); err != nil {
			t.Fatal(err)
		}
		if err := s.Health(ctx, pair[1]); err != nil {
			t.Fatal(err)
		}
		mustRunVPN(t, runner, "ip", "netns", "exec", netns, "ping", "-c", "1", "-W", "2", "10.253.97.1")
		after, err := runner.Run(ctx, "wg", "show", serverName, "latest-handshakes")
		if err != nil || after != handshake {
			t.Fatalf("rename reset handshake: %v", err)
		}
	}
	channelEdit.VPNServers = append([]config.VPNServer(nil), next.VPNServers...)
	channelEdit.VPNServers[0].DefaultChannel = "alternate"
	channelEdit.VPNServers[0].Peers = append([]config.VPNPeer(nil), next.VPNServers[0].Peers...)
	channelEdit.VPNServers[0].Peers[0].Channel = "peer-channel"
	stored := next
	stored.VPNServers = append([]config.VPNServer(nil), next.VPNServers...)
	stored.VPNServers[0].Peers = append([]config.VPNPeer(nil), next.VPNServers[0].Peers...)
	_, storedPublic := wgKeypair(t)
	stored.VPNServers[0].Peers = append(stored.VPNServers[0].Peers, config.VPNPeer{ID: "stored", Name: "Disabled peer", Address: "10.253.97.3", Credentials: map[string]string{"public_key": storedPublic}})
	livePeers, err := runner.Run(ctx, "wg", "show", serverName, "peers")
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]*config.Config{{&next, &stored}, {&stored, &next}} {
		if actions, err := s.Plan(pair[0], pair[1]); err != nil || len(actions) != 0 {
			t.Fatalf("disabled peer plan: %v %v", actions, err)
		}
		if err := s.Apply(ctx, pair[1]); err != nil {
			t.Fatal(err)
		}
		if err := s.Health(ctx, pair[1]); err != nil {
			t.Fatal(err)
		}
		peers, err := runner.Run(ctx, "wg", "show", serverName, "peers")
		if err != nil || peers != livePeers {
			t.Fatalf("disabled peer changed live peers: %v", err)
		}
		mustRunVPN(t, runner, "ip", "netns", "exec", netns, "ping", "-c", "1", "-W", "2", "10.253.97.1")
	}
	for _, pair := range [][2]*config.Config{{&next, &channelEdit}, {&channelEdit, &next}} {
		if actions, err := s.Plan(pair[0], pair[1]); err != nil || len(actions) != 0 {
			t.Fatalf("routing-only server plan: %v %v", actions, err)
		}
		for i := 0; i < 2; i++ {
			if err := s.Apply(ctx, pair[1]); err != nil {
				t.Fatal(err)
			}
			if err := s.Health(ctx, pair[1]); err != nil {
				t.Fatal(err)
			}
			mustRunVPN(t, runner, "ip", "netns", "exec", netns, "ping", "-c", "1", "-W", "2", "10.253.97.1")
			after, err := runner.Run(ctx, "wg", "show", serverName, "latest-handshakes")
			if err != nil || after != handshake {
				t.Fatalf("channel edit reset handshake: %v", err)
			}
		}
	}
	if err := s.Apply(ctx, config.Default()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join("/sys/class/net", serverName)); !os.IsNotExist(err) {
		t.Fatalf("серверный интерфейс не удалён: %v", err)
	}
}

func wgKeypair(t *testing.T) (string, string) {
	t.Helper()
	privateBytes, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		t.Fatal(err)
	}
	privateKey := strings.TrimSpace(string(privateBytes))
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(privateKey + "\n")
	publicBytes, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, strings.TrimSpace(string(publicBytes))
}

func mustRunVPN(t *testing.T, runner system.Runner, name string, args ...string) {
	t.Helper()
	if out, err := runner.Run(context.Background(), name, args...); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}
