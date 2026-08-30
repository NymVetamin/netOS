package channels

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type channelRunner struct {
	s        *Subsystem
	commands []string
	addr     string
	routes   string
	rules    string
}

func (r *channelRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	switch {
	case command == "ip link add name wg-ch1 type wireguard":
		if err := os.MkdirAll(filepath.Join(r.s.SysClassNet, "wg-ch1"), 0o755); err != nil {
			return "", err
		}
		path := filepath.Join(r.s.ProcSysNet, "ipv6", "conf", "wg-ch1")
		if err := os.MkdirAll(path, 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(path, "disable_ipv6"), []byte("0"), 0o644); err != nil {
			return "", err
		}
	case command == "wg show wg-ch1":
		if !r.s.linkExists("wg-ch1") {
			return "", errors.New("missing")
		}
		return "interface: wg-ch1\n", nil
	case command == "ip -o -4 addr show dev wg-ch1":
		return r.addr, nil
	case strings.HasPrefix(command, "ip -4 addr add "):
		r.addr = "7: wg-ch1 inet 10.44.0.2/32 scope global wg-ch1\n"
	case command == "ip -4 route show table 1001":
		return r.routes, nil
	case strings.Contains(command, "route replace default dev wg-ch1"):
		r.routes += "default dev wg-ch1 proto netos metric 100\n"
	case strings.Contains(command, "route replace blackhole default"):
		r.routes += "blackhole default proto netos metric 1000\n"
	case command == "ip -4 route flush table 1001":
		r.routes = ""
	case command == "ip -4 rule show":
		return r.rules, nil
	case strings.Contains(command, "rule add fwmark 0x1001"):
		lookup := args[len(args)-1]
		r.rules = "10001: from all fwmark 0x1001 lookup " + lookup + "\n"
	case command == "ip -4 rule del priority 10001":
		r.rules = ""
	case command == "ip link delete wg-ch1":
		_ = os.RemoveAll(filepath.Join(r.s.SysClassNet, "wg-ch1"))
	}
	return "", nil
}

func (r *channelRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func channelConfig() *config.Config {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg := config.Default()
	cfg.Components = []config.Component{{ID: "wireguard", Installed: true}}
	cfg.Channels = append(cfg.Channels, config.Channel{
		ID: "wg-home", Index: 1, Name: "Домой", Enabled: true,
		Type: "wireguard", Mode: "tun", FailMode: "block",
		Config: map[string]any{
			"address": "10.44.0.2/32", "private_key": key,
			"peer_public_key": key, "endpoint": "vpn.example:51820",
			"allowed_ips": []string{"0.0.0.0/0"}, "persistent_keepalive": 25,
		},
	})
	return cfg
}

func newTestSubsystem(t *testing.T) (*Subsystem, *channelRunner) {
	t.Helper()
	root := t.TempDir()
	s := New(nil, filepath.Join(root, "state"))
	s.RTTablesPath = filepath.Join(root, "rt_tables")
	s.SysClassNet = filepath.Join(root, "sys", "class", "net")
	s.ProcSysNet = filepath.Join(root, "proc", "sys", "net")
	s.UnitDir = filepath.Join(root, "systemd")
	r := &channelRunner{s: s}
	s.Runner = r
	return s, r
}

func TestApplyCreatesWireGuardChannelAndKillSwitch(t *testing.T) {
	s, runner := newTestSubsystem(t)
	cfg := channelConfig()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	for _, want := range []string{
		"ip link add name wg-ch1 type wireguard",
		"wg syncconf wg-ch1",
		"route replace default dev wg-ch1",
		"route replace blackhole default",
		"rule add fwmark 0x1001 priority 10001 lookup 1001",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("нет команды %q:\n%s", want, joined)
		}
	}
	conf := filepath.Join(s.StateDir, "wg-ch1.conf")
	info, err := os.Stat(conf)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("секретный конфиг имеет права %o", info.Mode().Perm())
	}
	disabled, err := os.ReadFile(filepath.Join(s.ProcSysNet, "ipv6", "conf", "wg-ch1", "disable_ipv6"))
	if err != nil || string(disabled) != "1" {
		t.Fatalf("IPv6 не подавлен: %q, %v", disabled, err)
	}
}

func TestApplyRejectsForeignChannelInterface(t *testing.T) {
	s, _ := newTestSubsystem(t)
	if err := os.MkdirAll(filepath.Join(s.SysClassNet, "wg-ch1"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := s.Apply(context.Background(), channelConfig())
	if err == nil || !strings.Contains(err.Error(), "не принадлежит netOS") {
		t.Fatalf("чужой интерфейс принят: %v", err)
	}
}

func TestWireGuardNumbersAreStable(t *testing.T) {
	ch := config.Channel{Index: 17, Type: "wireguard"}
	if got := InterfaceName(ch); got != "wg-ch17" {
		t.Fatal(got)
	}
	if TableNumber(ch) != 1017 || Mark(ch) != 0x1011 || Priority(ch) != 10017 {
		t.Fatal(fmt.Sprintf("table=%d mark=%x priority=%d", TableNumber(ch), Mark(ch), Priority(ch)))
	}
}

func TestOpenConnectArtifactsKeepPasswordOutOfArguments(t *testing.T) {
	ch := config.Channel{Index: 2, Name: "Office", Type: "openconnect"}
	oc := config.OpenConnectChannelConfig{Server: "https://vpn.example.com", Username: "alice", Password: "top-secret", Protocol: "anyconnect", MTU: 1380}
	conf := renderOpenConnect(ch, oc, "/state/script", true)
	unit := renderOpenConnectUnit(ch, "/state/config", "/state/password")
	if strings.Contains(conf, oc.Password) || strings.Contains(unit, oc.Password) {
		t.Fatal("OpenConnect password leaked into config or systemd unit")
	}
	for _, want := range []string{"server=https://vpn.example.com", "interface=tun-ch2", "disable-ipv6", "mtu=1380"} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q:\n%s", want, conf)
		}
	}
	if !strings.Contains(unit, "StandardInput=file:/state/password") || !strings.Contains(unit, "--passwd-on-stdin") {
		t.Fatalf("password is not passed through protected stdin:\n%s", unit)
	}
}

func TestMonitorAppliesBlockAndRestoresChannel(t *testing.T) {
	s, runner := newTestSubsystem(t)
	cfg := channelConfig()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	ch := cfg.Channels[1]
	ch.Probe.FailThreshold = 1
	ch.Probe.RiseThreshold = 1
	state := &channelState{}
	s.record(context.Background(), cfg, ch, state, false)
	if !state.Down || strings.Contains(runner.routes, "default dev wg-ch1") || !strings.Contains(runner.routes, "blackhole default") {
		t.Fatalf("kill-switch not applied: down=%v routes=%q", state.Down, runner.routes)
	}
	s.record(context.Background(), cfg, ch, state, true)
	if state.Down || !strings.Contains(runner.routes, "default dev wg-ch1") || !strings.Contains(runner.rules, "lookup 1001") {
		t.Fatalf("channel not restored: down=%v routes=%q rules=%q", state.Down, runner.routes, runner.rules)
	}
}

func TestMonitorCanUseDirectOrFallback(t *testing.T) {
	s, runner := newTestSubsystem(t)
	cfg := channelConfig()
	ch := cfg.Channels[1]
	ch.Probe.FailThreshold = 1
	ch.FailMode = "direct"
	runner.rules = "10001: from all fwmark 0x1001 lookup 1001\n"
	s.record(context.Background(), cfg, ch, &channelState{}, false)
	if runner.rules != "" {
		t.Fatalf("direct fallback kept policy rule: %q", runner.rules)
	}

	fallback := ch
	fallback.ID = "backup"
	fallback.Index = 2
	fallback.Enabled = true
	cfg.Channels = append(cfg.Channels, fallback)
	ch.FailMode = "fallback"
	ch.Fallback = "backup"
	s.record(context.Background(), cfg, ch, &channelState{}, false)
	if !strings.Contains(runner.rules, "lookup 1002") {
		t.Fatalf("fallback table not selected: %q", runner.rules)
	}
}
