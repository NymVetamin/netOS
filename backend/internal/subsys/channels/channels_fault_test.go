package channels

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type wireGuardRestoreFaults struct {
	system.Runner
	applyErr error
	rollback bool
	faults   map[string]error
}

func (r *wireGuardRestoreFaults) Run(ctx context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	if !r.rollback && strings.HasPrefix(command, "ip link set dev wg-ch1 mtu ") {
		r.rollback = true
		return "", r.applyErr
	}
	if r.rollback && r.faults[command] != nil {
		return "", r.faults[command]
	}
	return r.Runner.Run(ctx, name, args...)
}

func TestExistingWireGuardReportsIncompleteRollback(t *testing.T) {
	ctx := context.Background()
	s, runner := newTestSubsystem(t)
	cfg := channelConfig()
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	r := &wireGuardRestoreFaults{Runner: runner, applyErr: errors.New("apply failed"), faults: map[string]error{
		"ip -4 addr flush dev wg-ch1":                                            errors.New("flush failed"),
		"ip -4 addr add 10.44.0.2/32 dev wg-ch1":                                 errors.New("first address failed"),
		"ip -4 addr add 10.44.0.3/32 dev wg-ch1":                                 errors.New("second address failed"),
		"ip link set dev wg-ch1 mtu 1420 up":                                     errors.New("restore MTU failed"),
		"ip -4 route replace blackhole default metric 1000 table 1001 proto 201": errors.New("restore route failed"),
		"ip -4 rule show":                                                        errors.New("restore rule failed"),
	}}
	runner.addr += "7: wg-ch1 inet 10.44.0.3/32 scope global wg-ch1\n"
	runner.routes = "default dev wg-ch1 proto netos metric 100\n"
	s.Runner = r
	err := s.Apply(ctx, cfg)
	if !errors.Is(err, r.applyErr) {
		t.Fatalf("lost apply error: %v", err)
	}
	for command, fault := range r.faults {
		if !errors.Is(err, fault) {
			t.Errorf("lost failure of %s: %v", command, err)
		}
	}
	s.Runner = runner
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestFirstWireGuardFailureLeavesNoUnownedArtifacts(t *testing.T) {
	for _, failure := range []string{"ip link add", "wg syncconf", "ip link set"} {
		t.Run(strings.ReplaceAll(failure, " ", "-"), func(t *testing.T) {
			s, runner := newTestSubsystem(t)
			runner.failOnce = failure
			ch := channelConfig().Channels[1]
			if _, err := s.applyWireGuard(context.Background(), ch, false, true); err == nil {
				t.Fatal("injected failure was ignored")
			}
			if s.linkExists(InterfaceName(ch)) {
				t.Fatal("orphan WireGuard interface remained")
			}
			if _, err := os.Stat(filepath.Join(s.StateDir, "wg-ch1.conf")); !os.IsNotExist(err) {
				t.Fatalf("orphan WireGuard config remained: %v", err)
			}
		})
	}
}

func TestExistingWireGuardUpdateRestoresPreviousRuntimeAndFile(t *testing.T) {
	for _, failure := range []string{"wg syncconf", "ip link set", "route replace default"} {
		t.Run(strings.ReplaceAll(failure, " ", "-"), func(t *testing.T) {
			s, runner := newTestSubsystem(t)
			cfg := channelConfig()
			if err := s.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			old := cfg.Channels[1]
			confPath := filepath.Join(s.StateDir, "wg-ch1.conf")
			before, err := os.ReadFile(confPath)
			if err != nil {
				t.Fatal(err)
			}
			oldRuntime := append([]byte(nil), runner.wgConfig...)
			updated := old
			newKey := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
			updated.Config = map[string]any{
				"address": "10.44.0.9/32", "private_key": newKey,
				"peer_public_key": newKey, "endpoint": "new.example:51820",
				"allowed_ips": []string{"0.0.0.0/0"}, "persistent_keepalive": 15,
			}
			if failure == "route replace default" {
				runner.routes = ""
			}
			runner.failOnce, runner.failed = failure, false
			if _, err := s.applyWireGuard(context.Background(), updated, true, true); err == nil {
				t.Fatal("injected update failure was ignored")
			}
			after, err := os.ReadFile(confPath)
			if err != nil || string(after) != string(before) {
				t.Fatalf("WireGuard file not rolled back: before=%q after=%q err=%v", before, after, err)
			}
			if string(runner.wgConfig) != string(oldRuntime) {
				t.Fatalf("WireGuard runtime not rolled back: before=%q after=%q", oldRuntime, runner.wgConfig)
			}
			if !strings.Contains(runner.addr, "10.44.0.2/32") || strings.Contains(runner.addr, "10.44.0.9/32") {
				t.Fatalf("WireGuard address not rolled back: %q", runner.addr)
			}
			if err := s.Health(context.Background(), cfg); err != nil {
				t.Fatalf("previous channel unhealthy after rollback: %v", err)
			}
		})
	}
}

func serviceTestChannel(kind string) config.Channel {
	if kind == "openconnect" {
		return config.Channel{ID: "oc", Index: 3, Name: "Office", Enabled: true, Type: kind, Mode: "tun", FailMode: "block", Config: map[string]any{
			"server": "https://vpn.example.test", "username": "alice", "password": "old-secret", "protocol": "anyconnect", "mtu": 1380,
		}}
	}
	return testXrayChannel()
}

func serviceArtifactPaths(s *Subsystem, ch config.Channel) []string {
	if ch.Type == "openconnect" {
		conf, password, script, unit := s.openConnectPaths(ch)
		return []string{conf, password, script, unit}
	}
	conf, unit := s.xrayPaths(ch)
	return []string{conf, unit}
}

func applyServiceChannel(s *Subsystem, ch config.Channel, owned bool) (bool, error) {
	if ch.Type == "openconnect" {
		return s.applyOpenConnect(context.Background(), ch, owned, true)
	}
	return s.applyXray(context.Background(), ch, owned, true)
}

func TestFirstServiceChannelFailureLeavesNoUnownedArtifacts(t *testing.T) {
	for _, kind := range []string{"openconnect", "xray"} {
		for _, failure := range []string{"systemctl daemon-reload", "systemctl enable", "systemctl restart"} {
			t.Run(kind+"/"+strings.ReplaceAll(failure, " ", "-"), func(t *testing.T) {
				s, _ := newTestSubsystem(t)
				runner := &serviceLifecycleRunner{s: s, active: map[string]bool{}, enabled: map[string]bool{}, routes: map[string]string{}, failOnce: failure}
				s.Runner = runner
				ch := serviceTestChannel(kind)
				if _, err := applyServiceChannel(s, ch, false); err == nil {
					t.Fatal("injected failure was ignored")
				}
				for _, path := range serviceArtifactPaths(s, ch) {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Errorf("orphan artifact %s: %v", path, err)
					}
				}
				if s.linkExists(InterfaceName(ch)) {
					t.Fatal("orphan TUN remained after failed first install")
				}
			})
		}
	}
}

func TestExistingServiceChannelUpdateRestoresExactPreviousFiles(t *testing.T) {
	for _, kind := range []string{"openconnect", "xray"} {
		for _, failure := range []string{"systemctl daemon-reload", "systemctl restart"} {
			t.Run(kind+"/"+strings.ReplaceAll(failure, " ", "-"), func(t *testing.T) {
				s, _ := newTestSubsystem(t)
				runner := &serviceLifecycleRunner{s: s, active: map[string]bool{}, enabled: map[string]bool{}, routes: map[string]string{}}
				s.Runner = runner
				old := serviceTestChannel(kind)
				if created, err := applyServiceChannel(s, old, false); err != nil || !created {
					t.Fatalf("initial apply: created=%v err=%v", created, err)
				}
				paths := serviceArtifactPaths(s, old)
				before := make(map[string][]byte, len(paths))
				for _, path := range paths {
					before[path], _ = os.ReadFile(path)
				}

				updated := old
				if kind == "openconnect" {
					updated.Config = map[string]any{"server": "https://new.example.test", "username": "bob", "password": "new-secret", "mtu": 1410}
				} else {
					updated.Config = map[string]any{"mtu": 1450, "outbound": map[string]any{"protocol": "blackhole", "settings": map[string]any{}}}
				}
				runner.failOnce, runner.failed = failure, false
				if _, err := applyServiceChannel(s, updated, true); err == nil {
					t.Fatal("injected update failure was ignored")
				}
				for _, path := range paths {
					after, err := os.ReadFile(path)
					if err != nil || string(after) != string(before[path]) {
						t.Errorf("artifact not rolled back %s: before=%q after=%q err=%v", filepath.Base(path), before[path], after, err)
					}
				}
				unit := xrayUnitName(old)
				if kind == "openconnect" {
					unit = openConnectUnitName(old)
				}
				if !runner.active[unit] {
					t.Fatal("previous service was not restarted")
				}
			})
		}
	}
}

func TestHealthAndPlanDetectManagedChannelDrift(t *testing.T) {
	s, _ := newTestSubsystem(t)
	runner := &serviceLifecycleRunner{s: s, active: map[string]bool{}, enabled: map[string]bool{}, routes: map[string]string{}}
	s.Runner = runner
	ch := serviceTestChannel("xray")
	cfg := config.Default()
	cfg.Channels = []config.Channel{ch}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	conf, _ := s.xrayPaths(ch)
	if err := os.WriteFile(conf, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "расходится") {
		t.Fatalf("corrupt artifact Health=%v", err)
	}
	actions, err := s.Plan(cfg, cfg)
	if err != nil || len(actions) != 1 || actions[0].Kind != "update" {
		t.Fatalf("drift Plan=%#v err=%v", actions, err)
	}
}

func TestTypeTransitionFailureRestoresPreviousChannel(t *testing.T) {
	s, _ := newTestSubsystem(t)
	runner := &serviceLifecycleRunner{s: s, active: map[string]bool{}, enabled: map[string]bool{}, routes: map[string]string{}}
	s.Runner = runner
	oldChannel := serviceTestChannel("xray")
	oldCfg := config.Default()
	oldCfg.Channels = []config.Channel{oldChannel}
	if err := s.Apply(context.Background(), oldCfg); err != nil {
		t.Fatal(err)
	}
	oldConf, oldUnit := s.xrayPaths(oldChannel)
	beforeConf, _ := os.ReadFile(oldConf)
	beforeUnit, _ := os.ReadFile(oldUnit)

	newChannel := serviceTestChannel("openconnect")
	newChannel.ID, newChannel.Index = oldChannel.ID, oldChannel.Index
	newCfg := config.Default()
	newCfg.Channels = []config.Channel{newChannel}
	runner.failOnce, runner.failed = "systemctl restart netos-openconnect", false
	if err := s.Apply(context.Background(), newCfg); err == nil {
		t.Fatal("replacement failure was ignored")
	}
	if data, err := os.ReadFile(oldConf); err != nil || string(data) != string(beforeConf) {
		t.Fatalf("old Xray config not restored: %q err=%v", data, err)
	}
	if data, err := os.ReadFile(oldUnit); err != nil || string(data) != string(beforeUnit) {
		t.Fatalf("old Xray unit not restored: %q err=%v", data, err)
	}
	owned, err := s.readOwned()
	if err != nil || len(owned) != 1 || owned[0].Type != "xray" {
		t.Fatalf("old ownership not restored: %#v err=%v", owned, err)
	}
	// Apply rewrote the table catalog before the replacement failed. Restore the
	// expected bytes here would hide an Apply-level rollback defect, so Health is
	// the final exact-state assertion.
	if err := s.Health(context.Background(), oldCfg); err != nil {
		t.Fatalf("old channel unhealthy after failed transition: %v", err)
	}
}

func TestDisabledHealthAndPlanRejectStaleOwnedState(t *testing.T) {
	s, _ := newTestSubsystem(t)
	cfg := config.Default()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.writeOwned([]ownedChannel{{Name: "wg-ch9", Index: 9, Type: "wireguard"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "owned") {
		t.Fatalf("stale disabled state Health=%v", err)
	}
	actions, err := s.Plan(cfg, cfg)
	if err != nil || len(actions) != 1 || actions[0].Kind != "update" {
		t.Fatalf("stale disabled state Plan=%#v err=%v", actions, err)
	}
}

func TestFailedDeleteAndCreateRestoresRoutingTableCatalog(t *testing.T) {
	s, _ := newTestSubsystem(t)
	runner := &serviceLifecycleRunner{s: s, active: map[string]bool{}, enabled: map[string]bool{}, routes: map[string]string{}}
	s.Runner = runner
	oldChannel := serviceTestChannel("xray")
	oldCfg := config.Default()
	oldCfg.Channels = []config.Channel{oldChannel}
	if err := s.Apply(context.Background(), oldCfg); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(s.RTTablesPath)
	if err != nil {
		t.Fatal(err)
	}
	newChannel := serviceTestChannel("openconnect")
	newChannel.ID, newChannel.Index = "replacement", 4
	newCfg := config.Default()
	newCfg.Channels = []config.Channel{newChannel}
	runner.failOnce, runner.failed = "systemctl restart netos-openconnect-ch4.service", false
	if err := s.Apply(context.Background(), newCfg); err == nil {
		t.Fatal("replacement failure was ignored")
	}
	after, err := os.ReadFile(s.RTTablesPath)
	if err != nil || string(after) != string(before) {
		t.Fatalf("routing table catalog not rolled back: before=%q after=%q err=%v", before, after, err)
	}
	if err := s.Health(context.Background(), oldCfg); err != nil {
		t.Fatalf("previous channel unhealthy after delete/create failure: %v", err)
	}
}

func TestXrayReloadAndRestartOnRepeatedApply(t *testing.T) {
	s, _ := newTestSubsystem(t)
	r := &serviceLifecycleRunner{s: s, active: map[string]bool{}, enabled: map[string]bool{}, routes: map[string]string{}}
	s.Runner = r
	ch := testXrayChannel()
	if _, err := applyServiceChannel(s, ch, false); err != nil {
		t.Fatal(err)
	}
	check := func(wantReload, wantRestart bool) {
		t.Helper()
		r.commands = nil
		if _, err := applyServiceChannel(s, ch, true); err != nil {
			t.Fatal(err)
		}
		commands := strings.Join(r.commands, "\n")
		if strings.Contains(commands, "systemctl daemon-reload") != wantReload ||
			strings.Contains(commands, "systemctl restart "+xrayUnitName(ch)) != wantRestart {
			t.Fatalf("expected reload=%v restart=%v, commands: %s", wantReload, wantRestart, commands)
		}
	}
	check(false, false)
	ch.Name = "Renamed"
	check(true, false)
	ch.Config["mtu"] = 1420
	check(true, true)
	_, unit := s.xrayPaths(ch)
	if err := os.WriteFile(unit, []byte("[Service]\nExecStart=/bin/false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	check(true, true)
	check(false, false)
}
