//go:build linux

package qos

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationCAKELifecycle(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root are required")
	}
	for _, command := range []string{"ip", "tc", "modprobe"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("%s is not installed", command)
		}
	}
	ctx := context.Background()
	runner := system.NewExec()
	const device = "nqos-test0"
	const peer = "nqos-test1"
	const ifb = "ifb-netos-91"
	for _, name := range []string{device, peer, ifb} {
		if _, err := runner.Run(ctx, "ip", "link", "show", "dev", name); err == nil {
			t.Skipf("refusing to reuse existing interface %s", name)
		}
	}
	_, _ = runner.Run(ctx, "modprobe", "ifb")
	_, _ = runner.Run(ctx, "modprobe", "sch_cake")
	if _, err := runner.Run(ctx, "ip", "link", "add", "name", device, "type", "veth", "peer", "name", peer); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = runner.Run(context.Background(), "tc", "qdisc", "del", "dev", device, "root")
		_, _ = runner.Run(context.Background(), "tc", "qdisc", "del", "dev", device, "ingress")
		_, _ = runner.Run(context.Background(), "ip", "link", "del", "dev", ifb)
		_, _ = runner.Run(context.Background(), "ip", "link", "del", "dev", device)
	})
	if _, err := runner.Run(ctx, "ip", "link", "set", "dev", device, "up"); err != nil {
		t.Fatal(err)
	}

	s := New(runner, t.TempDir())
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "uplink", Name: device, Type: "physical", Enabled: true}}
	cfg.WANs = []config.WAN{{ID: "test-wan", Index: 91, Interface: "uplink", Proto: "dhcp", Enabled: true}}
	cfg.QoS = config.QoS{Enabled: true, WANs: []config.QoSWAN{{WAN: "test-wan", UploadKbit: 8000, DownloadKbit: 12000, Diffserv: "diffserv4"}}}
	// Stored settings while disabled must neither ask for confirmation nor
	// replace any live qdisc. Enabling below still exercises the full lifecycle.
	disabled := *cfg
	disabled.QoS.Enabled = false
	before, err := runner.Run(ctx, "tc", "qdisc", "show", "dev", device)
	if err != nil {
		t.Fatal(err)
	}
	for _, previous := range []*config.Config{config.Default(), &disabled} {
		if actions, err := s.Plan(previous, &disabled); err != nil || len(actions) != 0 {
			t.Fatalf("disabled settings plan=%+v err=%v", actions, err)
		}
		if err := s.Apply(ctx, &disabled); err != nil {
			t.Fatal(err)
		}
	}
	after, err := runner.Run(ctx, "tc", "qdisc", "show", "dev", device)
	if err != nil || before != after {
		t.Fatalf("disabled settings changed queues: before=%q after=%q err=%v", before, after, err)
	}
	if actions, err := s.Plan(&disabled, cfg); err != nil || len(actions) != 1 || !actions[0].Disruptive {
		t.Fatalf("enable plan=%+v err=%v", actions, err)
	}
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{device, ifb} {
		out, err := runner.Run(ctx, "tc", "qdisc", "show", "dev", name)
		if err != nil || !strings.Contains(out, "cake") {
			t.Fatalf("CAKE is not active on %s: %s (%v)", name, out, err)
		}
	}
	// A second apply must reuse the owned IFB instead of colliding with it.
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	cfg.QoS.Enabled = false
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(ctx, "ip", "link", "show", "dev", ifb); err == nil {
		t.Fatal("owned IFB remained after disabling QoS")
	}
}

func TestIntegrationClientRateLimits(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root are required")
	}
	for _, command := range []string{"ip", "tc", "iperf3", "ping"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("%s is not installed", command)
		}
	}
	ctx := context.Background()
	runner := system.NewExec()
	const namespace = "netos-qos-client"
	const device = "nqos-lan0"
	const peer = "nqos-lan1"
	if _, err := runner.Run(ctx, "ip", "netns", "list"); err != nil {
		t.Fatal(err)
	}
	if out, _ := runner.Run(ctx, "ip", "netns", "list"); strings.Contains(out, namespace) {
		t.Skip("refusing to reuse existing test namespace")
	}
	if _, err := runner.Run(ctx, "ip", "link", "show", "dev", device); err == nil {
		t.Skip("refusing to reuse existing test interface")
	}
	if _, err := runner.Run(ctx, "ip", "netns", "add", namespace); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = runner.Run(context.Background(), "ip", "netns", "del", namespace) })
	if _, err := runner.Run(ctx, "ip", "link", "add", "name", device, "type", "veth", "peer", "name", peer); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = runner.Run(context.Background(), "ip", "link", "del", "dev", device) })
	for _, command := range [][]string{
		{"ip", "link", "set", "dev", peer, "netns", namespace},
		{"ip", "link", "set", "dev", device, "mtu", "8942"},
		{"ip", "netns", "exec", namespace, "ip", "link", "set", "dev", peer, "mtu", "8942"},
		{"ip", "address", "add", "192.0.2.1/30", "dev", device},
		{"ip", "link", "set", "dev", device, "up"},
		{"ip", "netns", "exec", namespace, "ip", "address", "add", "192.0.2.2/30", "dev", peer},
		{"ip", "netns", "exec", namespace, "ip", "link", "set", "dev", peer, "up"},
		{"ip", "netns", "exec", namespace, "ip", "link", "set", "dev", "lo", "up"},
	} {
		if _, err := runner.Run(ctx, command[0], command[1:]...); err != nil {
			t.Fatal(err)
		}
	}
	mac, err := runner.Run(ctx, "ip", "netns", "exec", namespace, "cat", "/sys/class/net/"+peer+"/address")
	if err != nil {
		t.Fatal(err)
	}
	s := New(runner, t.TempDir())
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: device, Type: "physical", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "home", Interface: "lan", RouterAddress: "192.0.2.1/30", Zone: "lan", Enabled: true}}
	cfg.Clients = []config.Client{{ID: "test-client", MAC: strings.TrimSpace(mac), Network: "home", DownKbit: 5000, UpKbit: 1000}}
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	// The ingress policer must accept packets that fit a jumbo LAN link.
	// tc's default police MTU is only 2 KiB and silently drops them.
	if out, err := runner.Run(ctx, "ip", "netns", "exec", namespace, "ping", "-c", "1", "-W", "2", "-M", "do", "-s", "3000", "192.0.2.1"); err != nil {
		t.Fatalf("jumbo client packet was dropped by the upload policer: %v: %s", err, out)
	}
	download := runIPerf(t, ctx, namespace, false)
	upload := runIPerf(t, ctx, namespace, true)
	if upload < 200_000 || upload > 2_500_000 {
		t.Fatalf("upload limiter is outside tolerance: %.0f bit/s", upload)
	}
	if download < 1_000_000 || download > 7_000_000 {
		t.Fatalf("download shaper is outside tolerance: %.0f bit/s", download)
	}
	counted := &rateCountingRunner{Runner: runner}
	s.Runner = counted
	download = runIPerf(t, ctx, namespace, false, func() {
		cfg.Clients[0].DownKbit = 3000
		if err := s.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
	})
	upload = runIPerf(t, ctx, namespace, true, func() {
		cfg.Clients[0].UpKbit = 500
		if err := s.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
	})
	if counted.qdiscDeletes != 0 || counted.classChanges != 1 || counted.filterChanges != 1 {
		t.Fatalf("live update rebuilt shared queues: %+v", counted)
	}
	if download < 1_000_000 || download > 6_000_000 || upload < 100_000 || upload > 1_500_000 {
		t.Fatalf("live update throughput: down %.0f up %.0f", download, upload)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	t.Logf("TCP sessions survived rate updates: down %.0f up %.0f bit/s", download, upload)
	limits := append([]config.Client(nil), cfg.Clients...)
	removed := runIPerf(t, ctx, namespace, false, func() {
		cfg.Clients = nil
		if err := s.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
	})
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	added := runIPerf(t, ctx, namespace, false, func() {
		cfg.Clients = limits
		if err := s.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
	})
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if removed < 1_000_000 || added < 1_000_000 || removed > 10_000_000 || added > 10_000_000 {
		t.Fatalf("add/remove transfer outside bounds: add %.0f remove %.0f", added, removed)
	}
	t.Logf("TCP survived first limit add/last limit removal: add %.0f remove %.0f bit/s", added, removed)
	// Upload-only shaping has no HTB root; updating its policer must still
	// preserve the established TCP connection and the ingress qdisc.
	cfg.Clients[0].DownKbit = 0
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	counted.qdiscDeletes, counted.classChanges, counted.filterChanges = 0, 0, 0
	upload = runIPerf(t, ctx, namespace, true, func() {
		cfg.Clients[0].UpKbit = 1000
		if err := s.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
	})
	if counted.qdiscDeletes != 0 || counted.classChanges != 0 || counted.filterChanges != 1 {
		t.Fatalf("upload-only update rebuilt queues: %+v", counted)
	}
	if upload < 100_000 || upload > 2_500_000 {
		t.Fatalf("upload-only rate %.0f", upload)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if counted.qdiscDeletes != 0 || counted.filterChanges != 1 {
		t.Fatal("repeat mutated upload-only queues")
	}
	t.Logf("TCP survived upload-only update: %.0f bit/s", upload)
	cfg.Clients = nil
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	out, _ := runner.Run(ctx, "tc", "qdisc", "show", "dev", device)
	if strings.Contains(out, "htb") || strings.Contains(out, "ingress") {
		t.Fatalf("client qdiscs remained after cleanup: %s", out)
	}
}

func runIPerf(t *testing.T, ctx context.Context, namespace string, reverse bool, during ...func()) float64 {
	t.Helper()
	runCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// The server lives in the client namespace. The control connection therefore
	// starts from the router and is not rejected by the production INPUT policy.
	port := "5201"
	if reverse {
		// A separate listener avoids a race with the one-shot server from the
		// previous direction while its TCP socket is still being released.
		port = "5202"
	}
	server := exec.CommandContext(runCtx, "ip", "netns", "exec", namespace, "iperf3", "-s", "-1", "-B", "192.0.2.2", "-p", port)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill() })
	time.Sleep(250 * time.Millisecond)
	args := []string{"-c", "192.0.2.2", "-p", port, "-t", "3", "-J"}
	if len(during) > 0 {
		args = append(args, "-b", "8M")
	}
	if reverse {
		args = append(args, "-R")
	}
	var output bytes.Buffer
	client := exec.CommandContext(runCtx, "iperf3", args...)
	client.Stdout = &output
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	if len(during) > 0 {
		time.Sleep(time.Second)
		for _, action := range during {
			action()
		}
	}
	err := client.Wait()
	out := output.Bytes()
	_ = server.Wait()
	if err != nil {
		t.Fatalf("iperf3 failed: %v: %s", err, out)
	}
	var result struct {
		End struct {
			SumReceived struct {
				BitsPerSecond float64 `json:"bits_per_second"`
			} `json:"sum_received"`
		} `json:"end"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatal(err)
	}
	return result.End.SumReceived.BitsPerSecond
}
