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
	outputs  map[string]string
	errors   map[string]error
	cleaned  map[string]bool
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	f.commands = append(f.commands, command)
	if err := f.errors[command]; err != nil {
		return "", err
	}
	if output, ok := f.outputs[command]; ok {
		return output, nil
	}
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
	if name == "tc" && len(args) >= 5 && args[0] == "qdisc" && args[1] == "replace" && args[2] == "dev" {
		if f.cleaned == nil {
			f.cleaned = map[string]bool{}
		}
		f.cleaned[args[3]] = false
	}
	if name == "tc" && len(args) >= 5 && args[0] == "qdisc" && args[1] == "del" && args[2] == "dev" {
		if f.cleaned == nil {
			f.cleaned = map[string]bool{}
		}
		f.cleaned[args[3]] = true
	}
	if name == "tc" && len(args) >= 2 && args[0] == "qdisc" && args[1] == "show" {
		dev := args[3]
		if f.cleaned[dev] {
			return "", nil
		}
		switch {
		case strings.HasPrefix(dev, "ifb-netos-"):
			return "qdisc cake 8002: root bandwidth 47.5Mbit diffserv4 nat wash ingress", nil
		case dev == "lan0":
			return "qdisc htb 1: root default 1\nqdisc ingress ffff: parent ffff:fff1", nil
		default:
			return "qdisc cake 8001: root bandwidth 9.5Mbit diffserv4 nat\nqdisc ingress ffff: parent ffff:fff1", nil
		}
	}
	if command == "tc filter show dev eth9 parent ffff:" || command == "tc filter show dev ppp-wan1 parent ffff:" {
		return "filter pref 49152 u32 mirred egress redirect dev ifb-netos-3", nil
	}
	if command == "tc class show dev lan0" {
		return "class htb 1:1 root rate 10gbit ceil 10gbit\nclass htb 1:10 parent 1:1 rate 5Mbit ceil 5Mbit", nil
	}
	if command == "tc filter show dev lan0 parent 1:" {
		return "filter protocol all pref 100 flower dst_mac aa:bb:cc:dd:ee:ff classid 1:10", nil
	}
	if command == "tc filter show dev lan0 parent ffff:" {
		return "filter protocol all pref 100 flower src_mac aa:bb:cc:dd:ee:ff action police rate 1Mbit", nil
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

func TestClientLimitsCreateMACFiltersAndCleanup(t *testing.T) {
	runner := &fakeRunner{links: map[string]bool{"lan0": true}}
	s := New(runner, t.TempDir())
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "lan0", Type: "bridge", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "home", Interface: "lan", Enabled: true}}
	cfg.Clients = []config.Client{{ID: "phone", MAC: "aa:bb:cc:dd:ee:ff", Network: "home", DownKbit: 5000, UpKbit: 1000}}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	for _, want := range []string{
		"tc qdisc replace dev lan0 root handle 1: htb default 1",
		"flower dst_mac aa:bb:cc:dd:ee:ff classid 1:10",
		"flower src_mac aa:bb:cc:dd:ee:ff action police rate 1000kbit",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q:\n%s", want, joined)
		}
	}
	runner.commands = nil
	cfg.Clients = nil
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "tc qdisc del dev lan0 root") || !strings.Contains(joined, "tc qdisc del dev lan0 ingress") {
		t.Fatalf("client QoS was not cleaned up:\n%s", joined)
	}
}
