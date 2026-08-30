package qos

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type fakeRunner struct {
	commands []string
	links    map[string]bool
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	f.commands = append(f.commands, command)
	if name == "ip" && len(args) >= 4 && args[0] == "link" && args[1] == "show" {
		if f.links[args[3]] {
			return args[3], nil
		}
		return "", fmt.Errorf("not found")
	}
	if name == "ip" && len(args) >= 4 && args[0] == "link" && args[1] == "add" {
		f.links[args[3]] = true
	}
	if name == "ip" && len(args) >= 4 && args[0] == "link" && args[1] == "del" {
		delete(f.links, args[3])
	}
	if name == "tc" && len(args) >= 2 && args[0] == "qdisc" && args[1] == "show" {
		return "qdisc cake 8001: root", nil
	}
	return "", nil
}

func (f *fakeRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return f.Run(ctx, name, args...)
}

func testConfig(proto string) *config.Config {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "uplink", Name: "eth9", Enabled: true, Type: "physical"}}
	cfg.WANs = []config.WAN{{ID: "wan1", Index: 3, Interface: "uplink", Enabled: true, Proto: proto}}
	cfg.QoS = config.QoS{Enabled: true, WANs: []config.QoSWAN{{WAN: "wan1", UploadKbit: 9500, DownloadKbit: 47500, Diffserv: "diffserv4"}}}
	return cfg
}

func TestApplyCreatesBothCakeDirectionsAndIsIdempotent(t *testing.T) {
	runner := &fakeRunner{links: map[string]bool{"eth9": true}}
	s := New(runner, t.TempDir())
	cfg := testConfig("dhcp")
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	for _, want := range []string{
		"tc qdisc replace dev eth9 root cake bandwidth 9500kbit diffserv4 nat",
		"tc filter replace dev eth9 parent ffff: protocol all",
		"tc qdisc replace dev ifb-netos-3 root cake bandwidth 47500kbit diffserv4 nat wash ingress",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("нет команды %q:\n%s", want, joined)
		}
	}
	before := len(runner.commands)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	for _, command := range runner.commands[before:] {
		if strings.Contains(command, "link add") {
			t.Fatalf("повторное применение создало IFB заново: %s", command)
		}
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
}

func TestPPPSessionInterfaceAndDisableCleanup(t *testing.T) {
	runner := &fakeRunner{links: map[string]bool{"ppp-wan1": true}}
	s := New(runner, t.TempDir())
	cfg := testConfig("pppoe")
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(runner.commands, "\n"), "dev ppp-wan1 root cake") {
		t.Fatal("QoS не использует интерфейс PPP-сессии")
	}
	runner.commands = nil
	cfg.QoS.Enabled = false
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "tc qdisc del dev ppp-wan1 root") || !strings.Contains(joined, "ip link del dev ifb-netos-3") {
		t.Fatalf("неполная уборка:\n%s", joined)
	}
}

func TestForeignIFBIsNotModified(t *testing.T) {
	runner := &fakeRunner{links: map[string]bool{"eth9": true, "ifb-netos-3": true}}
	err := New(runner, t.TempDir()).Apply(context.Background(), testConfig("dhcp"))
	if err == nil || !strings.Contains(err.Error(), "не принадлежит netOS") {
		t.Fatalf("ожидался отказ при конфликте IFB, получено %v", err)
	}
	for _, command := range runner.commands {
		if strings.HasPrefix(command, "tc ") {
			t.Fatalf("при конфликте изменена живая очередь: %s", command)
		}
	}
}
