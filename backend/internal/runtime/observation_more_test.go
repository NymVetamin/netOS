package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type observationRunner struct {
	output string
	err    error
	calls  []string
}

func (r *observationRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, strings.Join(append([]string{name}, args...), " "))
	return r.output, r.err
}

func (r *observationRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func writeRuntimeFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestInterfaceStatsReadsEveryFieldAndSkipsLoopback(t *testing.T) {
	root := t.TempDir()
	writeRuntimeFile(t, filepath.Join(root, "lo", "operstate"), "up\n")
	base := filepath.Join(root, "eth0")
	for path, value := range map[string]string{
		"address": "02:00:00:00:00:01\n", "mtu": "1500\n", "operstate": "unknown\n", "flags": "0x1\n",
		"statistics/rx_bytes": "101\n", "statistics/tx_bytes": "202\n",
		"statistics/rx_packets": "11\n", "statistics/tx_packets": "22\n",
		"statistics/rx_errors": "1\n", "statistics/tx_errors": "2\n",
	} {
		writeRuntimeFile(t, filepath.Join(base, filepath.FromSlash(path)), value)
	}
	collector := NewCollector(&observationRunner{}, "")
	collector.SysClassNet = root
	stats, err := collector.InterfaceStats()
	if err != nil || len(stats) != 1 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
	want := InterfaceStat{Name: "eth0", Up: true, MAC: "02:00:00:00:00:01", MTU: 1500, RXBytes: 101, TXBytes: 202, RXPackets: 11, TXPackets: 22, RXErrors: 1, TXErrors: 2}
	if !reflect.DeepEqual(stats[0], want) {
		t.Fatalf("stat=%+v want=%+v", stats[0], want)
	}

	collector.SysClassNet = filepath.Join(root, "missing")
	if _, err := collector.InterfaceStats(); err == nil {
		t.Fatal("missing sysfs root accepted")
	}
}

func TestRoutesRulesAndConntrackObservation(t *testing.T) {
	runner := &observationRunner{output: strings.Join([]string{
		"default via 192.0.2.1 dev eth0 proto dhcp src 192.0.2.2 metric 100",
		"blackhole 10.0.0.0/8 proto 201 metric 7",
		"unreachable default proto static metric invalid",
		"local 192.0.2.2 dev eth0 proto kernel",
		"throw 203.0.113.0/24",
		"blackhole",
	}, "\n")}
	collector := NewCollector(runner, "")
	routes, err := collector.ParsedRoutes(context.Background(), "3001")
	if err != nil || len(routes) != 5 {
		t.Fatalf("routes=%+v err=%v", routes, err)
	}
	if routes[0].Type != "unicast" || routes[0].Destination != "default" || routes[0].Gateway != "192.0.2.1" || routes[0].Interface != "eth0" || routes[0].Source != "192.0.2.2" || routes[0].Metric != 100 || routes[0].Origin != "dhcp" || routes[0].Table != "3001" {
		t.Fatalf("default route=%+v", routes[0])
	}
	if routes[1].Type != "blackhole" || routes[1].Destination != "10.0.0.0/8" || routes[1].Origin != "netos" {
		t.Fatalf("blackhole route=%+v", routes[1])
	}
	if routes[2].Type != "unreachable" || routes[2].Destination != "default" || routes[2].Metric != 0 {
		t.Fatalf("unreachable route=%+v", routes[2])
	}
	if routes[3].Type != "local" || routes[4].Type != "throw" {
		t.Fatalf("typed routes=%+v", routes[3:])
	}
	if got := runner.calls[0]; got != "ip -4 route show table 3001" {
		t.Fatalf("route call=%q", got)
	}

	runner.output = "0: from all lookup local\n"
	if rules, err := collector.Rules(context.Background()); err != nil || rules != runner.output {
		t.Fatalf("rules=%q err=%v", rules, err)
	}
	if got := runner.calls[len(runner.calls)-1]; got != "ip -4 rule show" {
		t.Fatalf("rule call=%q", got)
	}

	proc := t.TempDir()
	writeRuntimeFile(t, filepath.Join(proc, "nf_conntrack_count"), "42\n")
	collector.ProcNetfilter = proc
	if count := collector.ConntrackCount(); count != 42 {
		t.Fatalf("conntrack count=%d", count)
	}
	writeRuntimeFile(t, filepath.Join(proc, "nf_conntrack_count"), "invalid\n")
	if count := collector.ConntrackCount(); count != 0 {
		t.Fatalf("invalid conntrack count=%d", count)
	}
}

func TestRouteObservationPropagatesRunnerErrorsAndUsesMainTable(t *testing.T) {
	runner := &observationRunner{output: "default dev eth0\n"}
	collector := NewCollector(runner, "")
	routes, err := collector.ParsedRoutes(context.Background(), "")
	if err != nil || len(routes) != 1 || routes[0].Table != "main" || runner.calls[0] != "ip -4 route show" {
		t.Fatalf("routes=%+v calls=%v err=%v", routes, runner.calls, err)
	}
	runner.err = errors.New("ip failed")
	if _, err := collector.ParsedRoutes(context.Background(), "main"); !errors.Is(err, runner.err) {
		t.Fatalf("error=%v", err)
	}
	if _, err := collector.Routes(context.Background(), "main"); !errors.Is(err, runner.err) {
		t.Fatalf("raw error=%v", err)
	}
}
