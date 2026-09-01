package channels

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

type channelRunnerFunc func(context.Context, string, ...string) (string, error)

func (f channelRunnerFunc) Run(ctx context.Context, name string, args ...string) (string, error) {
	return f(ctx, name, args...)
}
func (f channelRunnerFunc) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return f(ctx, name, args...)
}

type serviceLifecycleRunner struct {
	s        *Subsystem
	commands []string
	active   map[string]bool
	enabled  map[string]bool
	routes   map[string]string
	rules    string
	failOnce string
	failed   bool
}

func (r *serviceLifecycleRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	if r.failOnce != "" && !r.failed && strings.Contains(command, r.failOnce) {
		r.failed = true
		return "", errors.New("injected failure: " + r.failOnce)
	}
	if name == "systemctl" && len(args) >= 2 {
		unit := args[len(args)-1]
		switch args[0] {
		case "is-active":
			if r.active[unit] {
				return "active\n", nil
			}
			return "inactive\n", errors.New("inactive")
		case "restart":
			r.active[unit] = true
			index := 3
			link := filepath.Join(r.s.SysClassNet, "tun-ch3")
			if err := os.MkdirAll(link, 0o755); err != nil {
				return "", err
			}
			proc := filepath.Join(r.s.ProcSysNet, "ipv6", "conf", "tun-ch3")
			if err := os.MkdirAll(proc, 0o755); err != nil {
				return "", err
			}
			if err := os.WriteFile(filepath.Join(proc, "disable_ipv6"), []byte("0"), 0o644); err != nil {
				return "", err
			}
			_ = index
		case "stop":
			r.active[unit] = false
			_ = os.RemoveAll(filepath.Join(r.s.SysClassNet, "tun-ch3"))
		case "enable":
			r.enabled[unit] = true
		case "is-enabled":
			if r.enabled[unit] {
				return "enabled\n", nil
			}
			return "disabled\n", errors.New("disabled")
		}
	}
	if name == "ip" {
		joined := strings.Join(args, " ")
		switch {
		case joined == "-4 rule show":
			return r.rules, nil
		case strings.Contains(joined, "rule add fwmark 0x1003"):
			r.rules = "10003: from all fwmark 0x1003 lookup 1003\n"
		case joined == "-4 rule del priority 10003":
			r.rules = ""
		case joined == "-4 route show table 1003":
			return r.routes["1003"], nil
		case strings.Contains(joined, "route replace default dev tun-ch3"):
			r.routes["1003"] += "default dev tun-ch3 metric 100\n"
		case strings.Contains(joined, "route replace blackhole default"):
			r.routes["1003"] += "blackhole default metric 1000\n"
		case joined == "-4 route flush table 1003":
			r.routes["1003"] = ""
		case joined == "link delete tun-ch3":
			_ = os.RemoveAll(filepath.Join(r.s.SysClassNet, "tun-ch3"))
		}
	}
	return "", nil
}

func (r *serviceLifecycleRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestMetadataEnabledAndPlan(t *testing.T) {
	s, _ := newTestSubsystem(t)
	if s.Name() != "channels" || InterfaceName(config.Channel{Type: "openconnect", Index: 2}) != "tun-ch2" || InterfaceName(config.Channel{Type: "unknown", Index: 2}) != "ch2" {
		t.Fatal("channel metadata mismatch")
	}
	old := config.Default()
	next := config.Default()
	next.Channels = append(next.Channels,
		config.Channel{ID: "later", Index: 5, Name: "Later", Enabled: true, Type: "xray"},
		config.Channel{ID: "first", Index: 2, Name: "First", Enabled: true, Type: "openconnect"},
		config.Channel{ID: "ignored", Index: 3, Enabled: true, Type: "l2tp"},
	)
	if got := enabledChannels(next); len(got) != 2 || got[0].Index != 2 || got[1].Index != 5 {
		t.Fatalf("enabledChannels = %#v", got)
	}
	actions, err := s.Plan(nil, next)
	if err != nil || len(actions) != 2 || actions[0].Kind != "create" {
		t.Fatalf("initial Plan = %#v, %v", actions, err)
	}
	old.Channels = append(old.Channels, config.Channel{ID: "first", Index: 2, Name: "Old", Enabled: true, Type: "openconnect"}, config.Channel{ID: "gone", Index: 8, Name: "Gone", Enabled: true, Type: "wireguard"})
	actions, err = s.Plan(old, next)
	if err != nil || len(actions) != 3 {
		t.Fatalf("update Plan = %#v, %v", actions, err)
	}
	kinds := map[string]bool{}
	for _, action := range actions {
		kinds[action.Kind] = action.Disruptive
	}
	if !kinds["create"] || !kinds["update"] || !kinds["delete"] {
		t.Fatalf("Plan kinds = %#v", actions)
	}
}

func TestRuleMatchingIsExactAndDeleteFailureIsFatal(t *testing.T) {
	s, _ := newTestSubsystem(t)
	ch := config.Channel{Index: 1, Name: "qa"}
	rules := "10001: from all fwmark 0x9999 lookup 1001\n10002: from all fwmark 0x1001 lookup 10010\n"
	s.Runner = channelRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		if command == "ip -4 rule show" {
			return rules, nil
		}
		if command == "ip -4 rule del priority 10001" {
			return "", errors.New("delete refused")
		}
		return "", nil
	})
	if err := s.ensureRule(ctx(), ch); err == nil || !strings.Contains(err.Error(), "delete refused") {
		t.Fatalf("ensureRule error = %v", err)
	}
	if hasChannelRuleLine(rules, "10001", "0x1001", "1001", "netos-ch1") {
		t.Fatal("cross-line/substr rule accepted")
	}
	if !hasChannelRuleLine("10001: from all fwmark 0x1001 lookup netos-ch1", "10001", "0x1001", "1001", "netos-ch1") {
		t.Fatal("exact named rule rejected")
	}
}

func TestHealthRequiresExactRuleAndRouteAndSkipsDisabled(t *testing.T) {
	s, _ := newTestSubsystem(t)
	if err := s.Apply(context.Background(), config.Default()); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), config.Default()); err != nil {
		t.Fatal(err)
	}
	ch := testXrayChannel()
	cfg := config.Default()
	cfg.Channels = append(cfg.Channels, ch)
	if err := s.writeOwned([]ownedChannel{{Name: InterfaceName(ch), Index: ch.Index, Type: ch.Type, Unit: xrayUnitName(ch)}}); err != nil {
		t.Fatal(err)
	}
	if err := s.writeTables(enabledChannels(cfg)); err != nil {
		t.Fatal(err)
	}
	conf, unit := s.xrayPaths(ch)
	data, err := RenderXray(ch)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileIfChanged(conf, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileIfChanged(unit, []byte(renderXrayUnit(ch, conf)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(s.SysClassNet, InterfaceName(ch)), 0o755); err != nil {
		t.Fatal(err)
	}
	rules := "10003: from all fwmark 0x9999 lookup 1003\n10004: from all fwmark 0x1003 lookup 1003\n"
	routes := "default dev tun-ch30\nblackhole default\n"
	s.Runner = channelRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		switch command {
		case "ip -4 rule show":
			return rules, nil
		case "systemctl is-active netos-xray-ch3.service":
			return "active\n", nil
		case "systemctl is-enabled netos-xray-ch3.service":
			return "enabled\n", nil
		case "ip -4 route show table 1003":
			return routes, nil
		}
		return "", nil
	})
	if err := s.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "таблица") {
		t.Fatalf("wrong-device route Health = %v", err)
	}
	routes = "default dev tun-ch3\nblackhole default\n"
	if err := s.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "fwmark") {
		t.Fatalf("cross-line rule Health = %v", err)
	}
	rules = "10003: from all fwmark 0x1003 lookup 1003\n"
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
}

func TestForeignTunRejectedForOpenConnectAndXray(t *testing.T) {
	for _, ch := range []config.Channel{
		{Index: 2, Type: "openconnect", Config: map[string]any{}},
		testXrayChannel(),
	} {
		t.Run(ch.Type, func(t *testing.T) {
			s, _ := newTestSubsystem(t)
			if err := os.MkdirAll(filepath.Join(s.SysClassNet, InterfaceName(ch)), 0o755); err != nil {
				t.Fatal(err)
			}
			var err error
			if ch.Type == "openconnect" {
				_, err = s.applyOpenConnect(context.Background(), ch, false, true)
			} else {
				_, err = s.applyXray(context.Background(), ch, false, true)
			}
			if err == nil || !strings.Contains(err.Error(), "не принадлежит netOS") {
				t.Fatalf("foreign TUN accepted: %v", err)
			}
		})
	}
}

func TestOpenConnectAndXrayLifecycleWithServiceAndKernelState(t *testing.T) {
	for _, kind := range []string{"openconnect", "xray"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := newTestSubsystem(t)
			runner := &serviceLifecycleRunner{s: s, active: map[string]bool{}, enabled: map[string]bool{}, routes: map[string]string{}}
			s.Runner = runner
			ch := testXrayChannel()
			if kind == "openconnect" {
				ch = config.Channel{ID: "oc", Index: 3, Name: "Office", Enabled: true, Type: "openconnect", Mode: "tun", FailMode: "block", Config: map[string]any{
					"server": "https://vpn.example.test", "username": "alice", "password": "secret", "protocol": "anyconnect", "mtu": 1380,
				}}
			}
			var created bool
			var err error
			if kind == "openconnect" {
				created, err = s.applyOpenConnect(context.Background(), ch, false, true)
			} else {
				created, err = s.applyXray(context.Background(), ch, false, true)
			}
			if err != nil || !created {
				t.Fatalf("first apply = created %v, err %v", created, err)
			}
			cfg := config.Default()
			cfg.Channels = append(cfg.Channels, ch)
			unitName := xrayUnitName(ch)
			if kind == "openconnect" {
				unitName = openConnectUnitName(ch)
			}
			if err := s.writeOwned([]ownedChannel{{Name: InterfaceName(ch), Index: ch.Index, Type: ch.Type, Unit: unitName}}); err != nil {
				t.Fatal(err)
			}
			if err := s.writeTables(enabledChannels(cfg)); err != nil {
				t.Fatal(err)
			}
			if err := s.Health(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			disabled, err := os.ReadFile(filepath.Join(s.ProcSysNet, "ipv6", "conf", "tun-ch3", "disable_ipv6"))
			if err != nil || string(disabled) != "1" {
				t.Fatalf("IPv6 suppression = %q, %v", disabled, err)
			}
			if kind == "openconnect" {
				conf, password, script, unit := s.openConnectPaths(ch)
				for _, path := range []string{conf, password, script, unit} {
					if _, err := os.Stat(path); err != nil {
						t.Fatal(err)
					}
				}
				passwordData, _ := os.ReadFile(password)
				if string(passwordData) != "secret\n" {
					t.Fatalf("password artifact = %q", passwordData)
				}
				created, err = s.applyOpenConnect(context.Background(), ch, true, true)
				if err != nil || created {
					t.Fatalf("idempotent apply = created %v, err %v", created, err)
				}
				s.cleanupOpenConnect(context.Background(), ch)
				for _, path := range []string{conf, password, script, unit} {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatalf("artifact remained: %s", path)
					}
				}
			} else {
				conf, unit := s.xrayPaths(ch)
				for _, path := range []string{conf, unit} {
					if _, err := os.Stat(path); err != nil {
						t.Fatal(err)
					}
				}
				s.cleanupXray(context.Background(), ch)
				for _, path := range []string{conf, unit} {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatalf("artifact remained: %s", path)
					}
				}
			}
		})
	}
}

func TestTypeTransitionPreflightsReplacementBeforeOldCleanup(t *testing.T) {
	s, _ := newTestSubsystem(t)
	old := ownedChannel{Name: "tun-ch3", Index: 3, Type: "xray", Unit: "netos-xray-ch3.service"}
	if err := s.writeOwned([]ownedChannel{old}); err != nil {
		t.Fatal(err)
	}
	oldConf, oldUnit := s.xrayPaths(config.Channel{Index: 3})
	for _, path := range []string{oldConf, oldUnit} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var commands []string
	s.Runner = channelRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		commands = append(commands, command)
		return "", nil
	})
	cfg := config.Default()
	cfg.Channels = append(cfg.Channels, config.Channel{ID: "changed", Index: 3, Name: "Changed", Enabled: true, Type: "openconnect", Mode: "tun", Config: map[string]any{"mtu": "invalid"}})
	if err := s.Apply(context.Background(), cfg); err == nil {
		t.Fatal("invalid replacement unexpectedly applied")
	}
	joined := strings.Join(commands, "\n")
	if strings.Contains(joined, "systemctl stop netos-xray-ch3.service") {
		t.Fatalf("old unit was stopped before replacement preflight:\n%s", joined)
	}
	for _, path := range []string{oldConf, oldUnit} {
		if data, err := os.ReadFile(path); err != nil || string(data) != "old" {
			t.Fatalf("old artifact changed: %s data=%q err=%v", path, data, err)
		}
	}
}

func TestCleanupFailureDoesNotForgetOwnership(t *testing.T) {
	s, _ := newTestSubsystem(t)
	owned := ownedChannel{Name: "wg-ch7", Index: 7, Type: "wireguard"}
	if err := s.writeOwned([]ownedChannel{owned}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(s.SysClassNet, owned.Name), 0o755); err != nil {
		t.Fatal(err)
	}
	s.Runner = channelRunnerFunc(func(context.Context, string, ...string) (string, error) { return "", nil }) // link delete deliberately has no effect.
	if err := s.Apply(context.Background(), config.Default()); err == nil || !strings.Contains(err.Error(), "остался") {
		t.Fatalf("cleanup failure = %v", err)
	}
	got, err := s.readOwned()
	if err != nil || len(got) != 1 || got[0].Name != owned.Name {
		t.Fatalf("ownership lost after cleanup failure: %#v, %v", got, err)
	}
}

func TestProbeFamiliesHTTPAndTickLifecycle(t *testing.T) {
	s, _ := newTestSubsystem(t)
	var commands []string
	s.Runner = channelRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		commands = append(commands, name+" "+strings.Join(args, " "))
		return "", nil
	})
	for _, target := range []string{"192.0.2.1", "2001:db8::1"} {
		ch := config.Channel{Probe: config.Probe{Type: "icmp", Targets: []string{target}, Timeout: 2}}
		if !s.probe(context.Background(), ch, "tun0") {
			t.Fatalf("ICMP %s failed", target)
		}
	}
	if !strings.Contains(commands[0], "ping -4") || !strings.Contains(commands[1], "ping -6") {
		t.Fatalf("probe commands = %#v", commands)
	}
	commands = nil
	if !s.probe(context.Background(), config.Channel{Probe: config.Probe{Type: "http", Targets: []string{"https://example.test"}}}, "tun0") || !strings.Contains(commands[0], "curl --interface tun0") {
		t.Fatalf("HTTP probe commands = %#v", commands)
	}

	listener, err := net.Listen("tcp6", "[::1]:0")
	if err == nil {
		defer listener.Close()
		ch := config.Channel{Probe: config.Probe{Type: "tcp", Targets: []string{listener.Addr().String()}, Timeout: 1}}
		if !s.probe(context.Background(), ch, "") {
			t.Fatal("IPv6 TCP probe failed")
		}
	}

	cfg := channelConfig()
	ch := cfg.Channels[1]
	ch.Probe = config.Probe{Enabled: true, Type: "icmp", Targets: []string{"192.0.2.1"}, Interval: 1, FailThreshold: 1, RiseThreshold: 1}
	cfg.Channels[1] = ch
	s.states["stale"] = &channelState{}
	s.Probe = func(context.Context, config.Channel, string) bool { return true }
	s.pausedUntil = time.Now().Add(time.Minute)
	s.tick(context.Background(), cfg)
	if _, ok := s.states["stale"]; !ok {
		t.Fatal("paused tick changed states")
	}
	s.pausedUntil = time.Time{}
	s.tick(context.Background(), cfg)
	if _, ok := s.states["stale"]; ok || s.states[ch.ID] == nil {
		t.Fatalf("tick states = %#v", s.states)
	}
	s.tick(context.Background(), nil)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	s.Run(cancelled, func() *config.Config { return cfg })
}

func ctx() context.Context { return context.Background() }
