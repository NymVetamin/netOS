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

	"github.com/netos-router/netos/internal/apply"
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
	// ip netns exec bind-mounts files from /etc/netns/<name> over their host
	// counterparts.  Give the OpenConnect client a private resolv.conf so the
	// distribution vpnc-script cannot replace the router's live resolver while
	// the integration tunnel is connected (or leave it replaced after exit).
	netnsEtc := filepath.Join("/etc/netns", namespace)
	if _, err := os.Stat(netnsEtc); err == nil {
		t.Fatalf("refusing to reuse existing %s", netnsEtc)
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.MkdirAll(netnsEtc, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(netnsEtc) })
	if err := os.WriteFile(filepath.Join(netnsEtc, "resolv.conf"), []byte("nameserver 127.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
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
	changed := *cfg
	authBefore, err := os.ReadFile(s.ocservPaths(server).passwd)
	if err != nil {
		t.Fatal(err)
	}
	mixed := *cfg
	mixed.VPNServers = append([]config.VPNServer(nil), cfg.VPNServers...)
	mixed.VPNServers[0].Name = "Renamed"
	mixed.System.Hostname = "another-hostname"
	actions, err := s.Plan(cfg, &mixed)
	if err != nil || !apply.NeedsConfirmation(actions) {
		t.Fatalf("hostname change lost confirmation: %+v %v", actions, err)
	}
	mixed.System.Hostname = cfg.System.Hostname
	mixed.VPNServers[0].Port++
	actions, err = s.Plan(cfg, &mixed)
	if err != nil || !apply.NeedsConfirmation(actions) {
		t.Fatalf("port change lost confirmation: %+v %v", actions, err)
	}
	mixed.VPNServers[0].Port = cfg.VPNServers[0].Port
	unitPath := s.ocservPaths(server).unit
	savedUnit, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte("corrupt"), 0644); err != nil {
		t.Fatal(err)
	}
	actions, err = s.Plan(cfg, &mixed)
	restoreErr := os.WriteFile(unitPath, savedUnit, 0644)
	if err != nil || restoreErr != nil || !apply.NeedsConfirmation(actions) {
		t.Fatalf("server repair lost confirmation: %+v %v restore=%v", actions, err, restoreErr)
	}
	for _, name := range []string{"Renamed OpenConnect", "Renamed OpenConnect", server.Name} {
		previous := *cfg
		previous.VPNServers = append([]config.VPNServer(nil), cfg.VPNServers...)
		cfg.VPNServers[0].Name = name
		actions, err := s.Plan(&previous, cfg)
		if err != nil || apply.NeedsConfirmation(actions) {
			t.Fatalf("healthy server rename requires confirmation: %+v %v", actions, err)
		}
		if err := s.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if err := s.Health(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		started, err := runner.Run(ctx, "systemctl", "show", "-p", "ActiveEnterTimestampMonotonic", "--value", "netos-ocserv-srv998.service")
		if err != nil || started != startedBefore {
			t.Fatal("rename restarted ocserv")
		}
		authAfter, err := os.ReadFile(s.ocservPaths(server).passwd)
		if err != nil || !bytes.Equal(authBefore, authAfter) {
			t.Fatal("rename changed password file")
		}
		if _, err := runner.Run(ctx, "ip", "netns", "exec", namespace, "ping", "-c", "1", "-W", "2", "10.98.0.1"); err != nil {
			t.Fatalf("rename lost tunnel: %v", err)
		}
	}
	changed.VPNServers = append([]config.VPNServer(nil), cfg.VPNServers...)
	changed.VPNServers[0].DefaultChannel = "alternate"
	changed.VPNServers[0].Peers = append([]config.VPNPeer(nil), cfg.VPNServers[0].Peers...)
	changed.VPNServers[0].Peers[0].Channel = "alternate"
	for _, pair := range [][2]*config.Config{{cfg, &changed}, {&changed, cfg}} {
		if actions, err := s.Plan(pair[0], pair[1]); err != nil || len(actions) != 0 {
			t.Fatalf("channel-only plan: %v %v", actions, err)
		}
		for i := 0; i < 2; i++ {
			if err := s.Apply(ctx, pair[1]); err != nil {
				t.Fatal(err)
			}
			if err := s.Health(ctx, pair[1]); err != nil {
				t.Fatal(err)
			}
			started, err := runner.Run(ctx, "systemctl", "show", "-p", "ActiveEnterTimestampMonotonic", "--value", "netos-ocserv-srv998.service")
			if err != nil || started != startedBefore {
				t.Fatalf("channel edit restarted ocserv: %v", err)
			}
			if out, err := runner.Run(ctx, "ip", "netns", "exec", namespace, "ping", "-c", "1", "-W", "2", "10.98.0.1"); err != nil {
				t.Fatalf("channel edit lost tunnel: %s %v", out, err)
			}
		}
	}
	_ = client.Process.Kill()
	_, _ = client.Process.Wait()
	// Put the server side in the peer namespace for the outbound-channel
	// check: two tunnel endpoints in one namespace have overlapping local
	// addresses, so they cannot prove packet delivery through the tunnel.
	dropDir := "/etc/systemd/system/netos-ocserv-srv998.service.d"
	if _, err := os.Stat(dropDir); !os.IsNotExist(err) {
		t.Fatal("test drop-in directory already exists")
	}
	if err := os.Mkdir(dropDir, 0755); err != nil {
		t.Fatal(err)
	}
	dropFile := filepath.Join(dropDir, "qa-namespace.conf")
	t.Cleanup(func() {
		_ = os.Remove(dropFile)
		_ = os.Remove(dropDir)
		_, _ = runner.Run(context.Background(), "systemctl", "daemon-reload")
	})
	if err := os.WriteFile(dropFile, []byte("[Service]\nNetworkNamespacePath=/run/netns/"+namespace+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(ctx, "systemctl", "restart", "netos-ocserv-srv998.service"); err != nil {
		t.Fatal(err)
	}
	startedBefore, err = runner.Run(ctx, "systemctl", "show", "netos-ocserv-srv998.service", "-p", "ActiveEnterTimestampMonotonic", "--value")
	if err != nil {
		t.Fatal(err)
	}

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
			"server": "https://192.0.2.2:14443", "username": "integration",
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
	channelStamp, err := runner.Run(ctx, "systemctl", "show", "netos-openconnect-ch997.service", "-p", "ActiveEnterTimestampMonotonic", "--value")
	if err != nil {
		t.Fatal(err)
	}
	channelLink, err := runner.Run(ctx, "ip", "-o", "link", "show", "dev", "tun-ch997")
	if err != nil {
		t.Fatal(err)
	}
	mixedChannel := *channelCfg
	mixedChannel.Channels = append([]config.Channel(nil), channelCfg.Channels...)
	mixedChannel.Channels[len(mixedChannel.Channels)-1].Name = "Renamed"
	mixedChannel.IPv6.Mode = "passthrough"
	actions, err = channelSubsystem.Plan(channelCfg, &mixedChannel)
	if err != nil || !apply.NeedsConfirmation(actions) {
		t.Fatalf("IPv6 change lost confirmation: %+v %v", actions, err)
	}
	mixedChannel.IPv6 = channelCfg.IPv6
	channelUnit := "/etc/systemd/system/netos-openconnect-ch997.service"
	savedUnit, err = os.ReadFile(channelUnit)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(channelUnit, []byte("corrupt"), 0644); err != nil {
		t.Fatal(err)
	}
	actions, err = channelSubsystem.Plan(channelCfg, &mixedChannel)
	restoreErr = os.WriteFile(channelUnit, savedUnit, 0644)
	if err != nil || restoreErr != nil || !apply.NeedsConfirmation(actions) {
		t.Fatalf("channel repair lost confirmation: %+v %v restore=%v", actions, err, restoreErr)
	}
	for _, name := range []string{"Renamed outbound", "Renamed outbound", channel.Name} {
		previous := *channelCfg
		previous.Channels = append([]config.Channel(nil), channelCfg.Channels...)
		channelCfg.Channels[len(channelCfg.Channels)-1].Name = name
		actions, err := channelSubsystem.Plan(&previous, channelCfg)
		if err != nil || apply.NeedsConfirmation(actions) {
			t.Fatalf("healthy channel rename requires confirmation: %+v %v", actions, err)
		}
		if err := channelSubsystem.Apply(ctx, channelCfg); err != nil {
			t.Fatal(err)
		}
		if err := channelSubsystem.Health(ctx, channelCfg); err != nil {
			t.Fatal(err)
		}
		stamp, err := runner.Run(ctx, "systemctl", "show", "netos-openconnect-ch997.service", "-p", "ActiveEnterTimestampMonotonic", "--value")
		if err != nil || stamp != channelStamp {
			t.Fatal("rename restarted outbound OpenConnect")
		}
		link, err := runner.Run(ctx, "ip", "-o", "link", "show", "dev", "tun-ch997")
		if err != nil || link != channelLink {
			t.Fatal("rename replaced OpenConnect TUN")
		}
		if _, err := runner.Run(ctx, "ping", "-I", "tun-ch997", "-c", "1", "-W", "2", "10.98.0.1"); err != nil {
			t.Fatalf("outbound tunnel ping: %v", err)
		}
	}
	channelCfg.Channels[len(channelCfg.Channels)-1].Config["mtu"] = 1360
	if err := channelSubsystem.Apply(ctx, channelCfg); err != nil {
		t.Fatal(err)
	}
	if err := channelSubsystem.Health(ctx, channelCfg); err != nil {
		t.Fatal(err)
	}
	newStamp, err := runner.Run(ctx, "systemctl", "show", "netos-openconnect-ch997.service", "-p", "ActiveEnterTimestampMonotonic", "--value")
	if err != nil || newStamp == channelStamp {
		t.Fatal("MTU change did not restart outbound OpenConnect")
	}
	if _, err := runner.Run(ctx, "ping", "-I", "tun-ch997", "-c", "1", "-W", "2", "10.98.0.1"); err != nil {
		t.Fatalf("MTU reconnect lost tunnel: %v", err)
	}
	if err := channelSubsystem.Apply(ctx, config.Default()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/etc/systemd/system/netos-openconnect-ch997.service"); !os.IsNotExist(err) {
		t.Fatalf("OpenConnect channel unit was not removed: %v", err)
	}

	cfg.VPNServers[0].Config["mtu"] = 1360
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	newStamp, err = runner.Run(ctx, "systemctl", "show", "netos-ocserv-srv998.service", "-p", "ActiveEnterTimestampMonotonic", "--value")
	if err != nil || newStamp == startedBefore {
		t.Fatal("MTU change did not restart ocserv")
	}
	if err := s.Apply(ctx, config.Default()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join("/etc/systemd/system", "netos-ocserv-srv998.service")); !os.IsNotExist(err) {
		t.Fatalf("ocserv unit was not removed: %v", err)
	}
}
