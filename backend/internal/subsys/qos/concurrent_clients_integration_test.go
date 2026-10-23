//go:build linux

package qos

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationRateUpdatePreservesOtherClientTraffic(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root required")
	}
	for _, name := range []string{"ip", "tc", "iperf3"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("missing %s", name)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	runner := system.NewExec()
	run := func(name string, args ...string) {
		t.Helper()
		if out, err := runner.Run(ctx, name, args...); err != nil {
			t.Fatalf("%s %v: %v %s", name, args, err, out)
		}
	}
	const ns = "netos-qos-two"
	run("ip", "netns", "add", ns)
	t.Cleanup(func() { _, _ = runner.Run(context.Background(), "ip", "netns", "del", ns) })
	run("ip", "link", "add", "qos-two0", "type", "veth", "peer", "name", "qos-two1")
	t.Cleanup(func() { _, _ = runner.Run(context.Background(), "ip", "link", "del", "qos-two0") })
	run("ip", "link", "set", "qos-two1", "netns", ns)
	run("ip", "addr", "add", "192.0.2.1/24", "dev", "qos-two0")
	run("ip", "link", "set", "qos-two0", "up")
	run("ip", "netns", "exec", ns, "ip", "link", "set", "qos-two1", "up")
	run("ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "qos-two0", Type: "physical", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "home", Interface: "lan", RouterAddress: "192.0.2.1/24", Enabled: true}}
	for i := 0; i < 2; i++ {
		name := fmt.Sprintf("qos-c%d", i)
		mac := fmt.Sprintf("02:00:00:00:ab:%02d", i+1)
		run("ip", "netns", "exec", ns, "ip", "link", "add", "link", "qos-two1", "name", name, "address", mac, "type", "macvlan", "mode", "bridge")
		run("ip", "netns", "exec", ns, "ip", "addr", "add", fmt.Sprintf("192.0.2.%d/24", i+2), "dev", name)
		run("ip", "netns", "exec", ns, "ip", "link", "set", name, "up")
		cfg.Clients = append(cfg.Clients, config.Client{ID: name, MAC: mac, Network: "home", DownKbit: 4000 + i*2000})
	}
	s := New(runner, t.TempDir())
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	counted := &rateCountingRunner{Runner: runner}
	s.Runner = counted
	var clients, servers []*exec.Cmd
	outputs := []*bytes.Buffer{{}, {}}
	for i := 0; i < 2; i++ {
		ip := fmt.Sprintf("192.0.2.%d", i+2)
		port := fmt.Sprint(5231 + i)
		server := exec.CommandContext(ctx, "ip", "netns", "exec", ns, "iperf3", "-s", "-1", "-B", ip, "-p", port)
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = server.Process.Kill() })
		servers = append(servers, server)
		client := exec.CommandContext(ctx, "iperf3", "-c", ip, "-p", port, "-t", "8", "-b", "8M", "-J")
		client.Stdout = outputs[i]
		client.Stderr = outputs[i]
		clients = append(clients, client)
	}
	time.Sleep(250 * time.Millisecond)
	for _, client := range clients {
		if err := client.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Process.Kill() })
	}
	time.Sleep(3 * time.Second)
	cfg.Clients[0].DownKbit = 2000
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	for i, client := range clients {
		if err := client.Wait(); err != nil {
			t.Fatalf("client%d: %v %s", i, err, outputs[i])
		}
		if err := servers[i].Wait(); err != nil {
			t.Fatal(err)
		}
		var result struct {
			End struct {
				SumReceived struct {
					Rate float64 `json:"bits_per_second"`
				} `json:"sum_received"`
			} `json:"end"`
			Intervals []struct {
				Sum struct {
					Start, End float64
					Rate       float64 `json:"bits_per_second"`
				} `json:"sum"`
			} `json:"intervals"`
		}
		if err := json.Unmarshal(outputs[i].Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		rate := result.End.SumReceived.Rate
		if i == 0 && (rate < 1_000_000 || rate > 4_500_000) {
			t.Fatalf("changed client rate %.0f", rate)
		}
		if i == 1 {
			if rate < 4_000_000 || rate > 8_000_000 {
				t.Fatalf("other client rate %.0f", rate)
			}
			if len(result.Intervals) < 7 {
				t.Fatal("missing traffic intervals")
			}
			for _, interval := range result.Intervals {
				if interval.Sum.Start >= 1 && interval.Sum.End <= 7 && interval.Sum.Rate < 1_000_000 {
					t.Fatalf("other client stalled: %+v", interval)
				}
			}
		}
		t.Logf("client%d TCP completed, received %.0f bit/s", i, rate)
	}
	if counted.qdiscDeletes != 0 || counted.classChanges != 1 || counted.filterChanges != 0 {
		t.Fatalf("unexpected shared queue mutations: %+v", counted)
	}
	cfg.Clients[0].DownKbit = 4000
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Clients = nil
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
}
