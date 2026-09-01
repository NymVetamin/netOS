package vpnservers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type vpnRunnerFunc func(context.Context, string, ...string) (string, error)

func (f vpnRunnerFunc) Run(ctx context.Context, name string, args ...string) (string, error) {
	return f(ctx, name, args...)
}
func (f vpnRunnerFunc) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return f(ctx, name, args...)
}

type vpnServiceRunner struct {
	active   map[string]bool
	enabled  map[string]bool
	s        *Subsystem
	address  map[string]string
	linkUp   map[string]bool
	mtu      map[string]int
	failOn   string
	failAt   int
	failSeen int
	commands []string
}

func (r *vpnServiceRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	if r.failOn != "" && strings.Contains(command, r.failOn) {
		r.failSeen++
		if r.failAt == 0 || r.failSeen == r.failAt {
			return "", errors.New("injected " + r.failOn)
		}
	}
	if name == "ip" && r.s != nil {
		if r.address == nil {
			r.address = map[string]string{}
		}
		if r.linkUp == nil {
			r.linkUp, r.mtu = map[string]bool{}, map[string]int{}
		}
		switch {
		case len(args) >= 4 && args[0] == "link" && args[1] == "add":
			_ = os.MkdirAll(filepath.Join(r.s.SysClassNet, args[2]), 0o755)
		case len(args) >= 3 && args[0] == "link" && args[1] == "delete":
			_ = os.RemoveAll(filepath.Join(r.s.SysClassNet, args[2]))
			delete(r.linkUp, args[2])
			delete(r.mtu, args[2])
		case len(args) >= 7 && args[0] == "link" && args[1] == "set" && args[2] == "dev" && args[4] == "mtu":
			r.linkUp[args[3]] = true
			var mtu int
			_, _ = fmt.Sscan(args[5], &mtu)
			r.mtu[args[3]] = mtu
		case len(args) >= 5 && args[0] == "-o" && args[1] == "link" && args[2] == "show" && args[3] == "dev":
			flags := "BROADCAST"
			if r.linkUp[args[4]] {
				flags += ",UP"
			}
			return fmt.Sprintf("8: %s: <%s> mtu %d state UP link/none\n", args[4], flags, r.mtu[args[4]]), nil
		case len(args) >= 6 && args[0] == "-o" && args[1] == "-4" && args[2] == "addr" && args[3] == "show":
			return r.address[args[5]], nil
		case len(args) >= 6 && args[0] == "-4" && args[1] == "addr" && args[2] == "add":
			r.address[args[5]] = "8: " + args[5] + " inet " + args[3] + " scope global\n"
		case len(args) >= 5 && args[0] == "-4" && args[1] == "addr" && args[2] == "flush":
			delete(r.address, args[4])
		}
	}
	if name == "systemctl" && len(args) >= 2 {
		if r.enabled == nil {
			r.enabled = map[string]bool{}
		}
		unit := args[len(args)-1]
		switch args[0] {
		case "is-active":
			if r.active[unit] {
				return "active\n", nil
			}
			return "inactive\n", errors.New("inactive")
		case "restart":
			r.active[unit] = true
		case "is-enabled":
			if r.enabled[unit] {
				return "enabled\n", nil
			}
			return "disabled\n", errors.New("disabled")
		case "enable":
			r.enabled[unit] = true
		case "disable":
			r.enabled[unit] = false
		case "stop":
			r.active[unit] = false
		}
	}
	return "", nil
}
func (r *vpnServiceRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	if name == "ocpasswd" && len(args) >= 3 && args[0] == "-c" {
		line := args[2] + "::fake-crypt-hash\n"
		file, err := os.OpenFile(args[1], os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return "", err
		}
		if _, err := file.WriteString(line); err != nil {
			_ = file.Close()
			return "", err
		}
		if err := file.Close(); err != nil {
			return "", err
		}
	}
	return r.Run(ctx, name, args...)
}

func TestMetadataEnabledPlanAndPeerCIDR(t *testing.T) {
	s, _ := newTestSubsystem(t)
	s.UnitDir = filepath.Join(t.TempDir(), "units")
	if s.Name() != "vpn-servers" || InterfaceName(config.VPNServer{Type: "ocserv", Index: 2}) != "vpns2" || InterfaceName(config.VPNServer{Type: "ikev2", Index: 2}) != "xfrm-srv2" || resourceName(config.VPNServer{Type: "xray", Index: 2}) != "xray-srv2" {
		t.Fatal("VPN server metadata mismatch")
	}
	next := config.Default()
	next.VPNServers = []config.VPNServer{
		{ID: "later", Index: 5, Name: "Later", Enabled: true, Type: "xray"},
		{ID: "first", Index: 2, Name: "First", Enabled: true, Type: "ocserv"},
		{ID: "ignored", Index: 3, Enabled: true, Type: "pptp"},
	}
	if got := enabledServers(next); len(got) != 2 || got[0].Index != 2 || got[1].Index != 5 {
		t.Fatalf("enabledServers = %#v", got)
	}
	actions, err := s.Plan(nil, next)
	if err != nil || len(actions) != 2 || actions[0].Kind != "create" {
		t.Fatalf("initial Plan = %#v, %v", actions, err)
	}
	old := config.Default()
	old.VPNServers = []config.VPNServer{{ID: "first", Index: 2, Name: "Old", Enabled: true, Type: "ocserv"}, {ID: "gone", Index: 8, Name: "Gone", Enabled: true, Type: "wireguard"}}
	actions, err = s.Plan(old, next)
	if err != nil || len(actions) != 3 {
		t.Fatalf("update Plan = %#v, %v", actions, err)
	}
	if PeerCIDR(config.VPNPeer{Address: "10.0.0.2"}) != "10.0.0.2/32" || PeerCIDR(config.VPNPeer{Address: "bad"}) != "" {
		t.Fatal("PeerCIDR mismatch")
	}
	if !hasAddress("8: wg inet 10.0.0.1/24 scope global", "10.0.0.1/24") || hasAddress("8: wg inet 110.0.0.1/24", "10.0.0.1/24") {
		t.Fatal("address matching is not exact")
	}
}

func TestForeignXrayAndOcservUnitsAreRejected(t *testing.T) {
	for _, kind := range []string{"xray", "ocserv"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := newTestSubsystem(t)
			s.UnitDir = filepath.Join(t.TempDir(), "units")
			if err := os.MkdirAll(s.UnitDir, 0o755); err != nil {
				t.Fatal(err)
			}
			var server config.VPNServer
			if kind == "xray" {
				cfg, candidate := xrayServerConfig()
				server = candidate
				_, unit := s.xrayPaths(server)
				if err := os.WriteFile(unit, []byte("foreign"), 0o644); err != nil {
					t.Fatal(err)
				}
				if _, err := s.applyXray(context.Background(), cfg, server, false); err == nil || !strings.Contains(err.Error(), "не принадлежит") {
					t.Fatalf("foreign Xray unit accepted: %v", err)
				}
			} else {
				cfg, candidate := ocservConfig()
				server = candidate
				paths := s.ocservPaths(server)
				if err := os.WriteFile(paths.unit, []byte("foreign"), 0o644); err != nil {
					t.Fatal(err)
				}
				if _, err := s.applyOcserv(context.Background(), cfg, server, false); err == nil || !strings.Contains(err.Error(), "не принадлежит") {
					t.Fatalf("foreign ocserv unit accepted: %v", err)
				}
			}
		})
	}
}

func TestForeignIKEv2UnitIsRejected(t *testing.T) {
	s, _ := newTestSubsystem(t)
	s.UnitDir = filepath.Join(t.TempDir(), "units")
	if err := os.MkdirAll(s.UnitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	paths := s.ikev2Paths()
	if err := os.WriteFile(paths.unit, []byte("foreign"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	server := config.VPNServer{ID: "ike", Index: 7, Name: "IKE", Enabled: true, Type: "ikev2", Subnet: "10.7.0.1/24"}
	if err := s.applyIKEv2(context.Background(), cfg, []config.VPNServer{server}, false); err == nil || !strings.Contains(err.Error(), "не принадлежит") {
		t.Fatalf("foreign IKEv2 unit accepted: %v", err)
	}
}

func TestCleanupFailurePreservesOwnership(t *testing.T) {
	s, _ := newTestSubsystem(t)
	item := ownedServer{Name: "wg-srv7", Index: 7, Type: "wireguard"}
	if err := s.writeOwned([]ownedServer{item}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(s.SysClassNet, item.Name), 0o755); err != nil {
		t.Fatal(err)
	}
	s.Runner = vpnRunnerFunc(func(context.Context, string, ...string) (string, error) { return "", nil })
	if err := s.Apply(context.Background(), config.Default()); err == nil || !strings.Contains(err.Error(), "остался") {
		t.Fatalf("cleanup failure = %v", err)
	}
	owned, err := s.readOwned()
	if err != nil || len(owned) != 1 || owned[0].Name != item.Name {
		t.Fatalf("ownership lost: %#v, %v", owned, err)
	}
}

func TestXrayServerFakeServiceLifecycle(t *testing.T) {
	s, _ := newTestSubsystem(t)
	s.UnitDir = filepath.Join(t.TempDir(), "units")
	runner := &vpnServiceRunner{active: map[string]bool{}}
	s.Runner = runner
	cfg, server := xrayServerConfig()
	cfg.VPNServers = []config.VPNServer{server}
	created, err := s.applyXray(context.Background(), cfg, server, false)
	if err != nil || !created {
		t.Fatalf("apply Xray = created %v, %v", created, err)
	}
	if err := s.writeOwned(ownedServersFor([]config.VPNServer{server})); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := s.applyXray(context.Background(), cfg, server, true); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	if strings.Count(joined, "systemctl enable "+xrayUnitName(server)) != 1 || strings.Count(joined, "systemctl restart "+xrayUnitName(server)) != 1 {
		t.Fatalf("clean Xray apply mutated systemd:\n%s", joined)
	}
	conf, unit := s.xrayPaths(server)
	if err := os.WriteFile(conf, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("corrupt Xray config passed health")
	}
	if _, err := s.applyXray(context.Background(), cfg, server, true); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{conf, unit} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.remove(context.Background(), ownedServer{Name: resourceName(server), Index: server.Index, Type: "xray", Unit: xrayUnitName(server)}); err != nil {
		t.Fatal(err)
	}
	if err := pathsAbsent(conf, unit); err != nil {
		t.Fatal(err)
	}
}

func TestOcservFakeServiceLifecycle(t *testing.T) {
	s, _ := newTestSubsystem(t)
	s.UnitDir = filepath.Join(t.TempDir(), "units")
	runner := &vpnServiceRunner{active: map[string]bool{}}
	s.Runner = runner
	cfg, server := ocservConfig()
	created, err := s.applyOcserv(context.Background(), cfg, server, false)
	if err != nil || !created {
		t.Fatalf("apply ocserv = created %v, %v", created, err)
	}
	if err := s.writeOwned(ownedServersFor([]config.VPNServer{server})); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := s.applyOcserv(context.Background(), cfg, server, true); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	if strings.Count(joined, "systemctl enable "+ocservUnitName(server)) != 1 || strings.Count(joined, "systemctl restart "+ocservUnitName(server)) != 1 {
		t.Fatalf("clean ocserv apply mutated systemd:\n%s", joined)
	}
	paths := s.ocservPaths(server)
	if err := os.WriteFile(paths.unit, []byte("corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("corrupt ocserv unit passed health")
	}
	if _, err := s.applyOcserv(context.Background(), cfg, server, true); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.passwd, []byte("phone::attacker-hash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("tampered ocserv passwd passed health")
	}
	if _, err := s.applyOcserv(context.Background(), cfg, server, true); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatalf("ocserv passwd was not repaired: %v", err)
	}
	userPath := filepath.Join(paths.users, "phone")
	if err := os.WriteFile(userPath, []byte("explicit-ipv4 = 10.30.0.99\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("tampered ocserv per-user address passed health")
	}
	if _, err := s.applyOcserv(context.Background(), cfg, server, true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.users, "intruder"), []byte("explicit-ipv4 = 10.30.0.99\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("extra ocserv per-user file passed health")
	}
	if _, err := s.applyOcserv(context.Background(), cfg, server, true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.auth, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("tampered ocserv integrity marker passed health")
	}
	if _, err := s.applyOcserv(context.Background(), cfg, server, true); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatalf("ocserv account artifacts were not repaired: %v", err)
	}
	if err := os.WriteFile(filepath.Join(paths.tls, "panel.key"), []byte("not a private key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("broken ocserv TLS key passed health")
	}
	if _, err := s.applyOcserv(context.Background(), cfg, server, true); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatalf("ocserv TLS pair was not repaired: %v", err)
	}
	for _, path := range []string{paths.conf, paths.passwd, paths.users, paths.tls, paths.unit} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.remove(context.Background(), ownedServer{Name: resourceName(server), Index: server.Index, Type: "ocserv", Unit: ocservUnitName(server)}); err != nil {
		t.Fatal(err)
	}
}

func TestServiceVPNHealthRequiresEnabledUnit(t *testing.T) {
	for _, server := range []config.VPNServer{
		{Index: 1, Name: "Xray", Enabled: true, Type: "xray"},
		{Index: 2, Name: "OpenConnect", Enabled: true, Type: "ocserv"},
	} {
		t.Run(server.Type, func(t *testing.T) {
			unit := xrayUnitName(server)
			if server.Type == "ocserv" {
				unit = ocservUnitName(server)
			}
			runner := &vpnServiceRunner{active: map[string]bool{unit: true}, enabled: map[string]bool{unit: false}}
			s, _ := newTestSubsystem(t)
			s.Runner = runner
			if err := s.unitActiveEnabled(context.Background(), unit); err == nil {
				t.Fatal("active but disabled VPN unit passed health")
			}
		})
	}
}

func TestIKEv2FakeServiceLifecycleAndIdempotency(t *testing.T) {
	s, _ := newTestSubsystem(t)
	s.UnitDir = t.TempDir()
	runner := &vpnServiceRunner{active: map[string]bool{}, s: s}
	s.Runner = runner
	cfg, server := ikev2TestConfig()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	paths := s.ikev2Paths()
	for _, path := range []string{paths.conf, paths.daemonConf, paths.cert, paths.key, paths.unit} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing IKEv2 artifact %s: %v", path, err)
		}
	}
	if !s.linkExists(InterfaceName(server)) {
		t.Fatal("IKEv2 XFRM interface was not created")
	}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	for command, want := range map[string]int{
		"systemctl enable " + ikev2Unit:                             1,
		"systemctl restart " + ikev2Unit:                            1,
		"systemctl daemon-reload":                                   1,
		"ip link set dev " + InterfaceName(server) + " mtu 1400 up": 1,
	} {
		if got := strings.Count(joined, command); got != want {
			t.Fatalf("command %q count=%d want=%d:\n%s", command, got, want, joined)
		}
	}
	name := InterfaceName(server)
	runner.mtu[name] = 1399
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("IKEv2 XFRM MTU drift passed health")
	}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if runner.mtu[name] != 1400 {
		t.Fatalf("IKEv2 XFRM MTU was not repaired: %d", runner.mtu[name])
	}
	runner.linkUp[name] = false
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("down IKEv2 XFRM interface passed health")
	}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if !runner.linkUp[name] {
		t.Fatal("IKEv2 XFRM interface was not brought back up")
	}
	if err := os.WriteFile(paths.key, []byte("not a private key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("broken IKEv2 TLS key passed health")
	}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatalf("IKEv2 TLS pair was not repaired: %v", err)
	}
	if err := os.WriteFile(paths.daemonConf, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("corrupt IKEv2 daemon config passed health")
	}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	runner.enabled[ikev2Unit] = false
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("active but disabled IKEv2 unit passed health")
	}
	runner.enabled[ikev2Unit] = true
	if err := s.Apply(context.Background(), config.Default()); err != nil {
		t.Fatal(err)
	}
	if s.linkExists(InterfaceName(server)) {
		t.Fatal("IKEv2 XFRM interface remained after cleanup")
	}
	for _, path := range []string{paths.root, paths.unit} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("IKEv2 artifact remained after cleanup %s: %v", path, err)
		}
	}
}

func TestNewServiceVPNFailureLeavesNoArtifactsOrOwnership(t *testing.T) {
	t.Run("xray", func(t *testing.T) {
		s, _ := newTestSubsystem(t)
		s.UnitDir = t.TempDir()
		runner := &vpnServiceRunner{active: map[string]bool{}, failOn: "daemon-reload"}
		s.Runner = runner
		cfg, server := xrayServerConfig()
		if _, err := s.applyXray(context.Background(), cfg, server, false); err == nil {
			t.Fatal("daemon-reload failure accepted")
		}
		conf, unit := s.xrayPaths(server)
		if err := pathsAbsent(conf, unit); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("ocserv", func(t *testing.T) {
		s, _ := newTestSubsystem(t)
		s.UnitDir = t.TempDir()
		runner := &vpnServiceRunner{active: map[string]bool{}, failOn: "daemon-reload"}
		s.Runner = runner
		cfg, server := ocservConfig()
		if _, err := s.applyOcserv(context.Background(), cfg, server, false); err == nil {
			t.Fatal("daemon-reload failure accepted")
		}
		paths := s.ocservPaths(server)
		if err := pathsAbsent(paths.conf, paths.passwd, paths.auth, paths.unit, paths.users, paths.tls); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("ikev2", func(t *testing.T) {
		s, _ := newTestSubsystem(t)
		s.UnitDir = t.TempDir()
		runner := &vpnServiceRunner{active: map[string]bool{}, failOn: "daemon-reload", s: s}
		s.Runner = runner
		cfg, server := ikev2TestConfig()
		if err := s.Apply(context.Background(), cfg); err == nil {
			t.Fatal("daemon-reload failure accepted")
		}
		paths := s.ikev2Paths()
		if err := pathsAbsent(paths.root, paths.unit, s.ownedPath()); err != nil {
			t.Fatal(err)
		}
		if s.linkExists(InterfaceName(server)) {
			t.Fatal("provisional IKEv2 interface remained")
		}
	})
}

func TestExistingServiceVPNFailureRestoresPreviousWorkingState(t *testing.T) {
	t.Run("xray", func(t *testing.T) {
		s, _ := newTestSubsystem(t)
		s.UnitDir = t.TempDir()
		runner := &vpnServiceRunner{active: map[string]bool{}}
		s.Runner = runner
		cfg, server := xrayServerConfig()
		cfg.VPNServers = []config.VPNServer{server}
		if _, err := s.applyXray(context.Background(), cfg, server, false); err != nil {
			t.Fatal(err)
		}
		if err := s.writeOwned(ownedServersFor([]config.VPNServer{server})); err != nil {
			t.Fatal(err)
		}
		conf, _ := s.xrayPaths(server)
		before, err := os.ReadFile(conf)
		if err != nil {
			t.Fatal(err)
		}
		updated := server
		updated.Port++
		runner.failOn, runner.failAt, runner.failSeen = "daemon-reload", 1, 0
		if _, err := s.applyXray(context.Background(), cfg, updated, true); err == nil {
			t.Fatal("Xray update failure accepted")
		}
		after, err := os.ReadFile(conf)
		if err != nil || string(after) != string(before) {
			t.Fatalf("Xray rollback changed config: err=%v", err)
		}
		if err := s.Health(context.Background(), cfg); err != nil {
			t.Fatalf("previous Xray state not healthy after rollback: %v", err)
		}
	})

	t.Run("ocserv", func(t *testing.T) {
		s, _ := newTestSubsystem(t)
		s.UnitDir = t.TempDir()
		runner := &vpnServiceRunner{active: map[string]bool{}}
		s.Runner = runner
		cfg, server := ocservConfig()
		if _, err := s.applyOcserv(context.Background(), cfg, server, false); err != nil {
			t.Fatal(err)
		}
		if err := s.writeOwned(ownedServersFor([]config.VPNServer{server})); err != nil {
			t.Fatal(err)
		}
		paths := s.ocservPaths(server)
		before, err := os.ReadFile(paths.conf)
		if err != nil {
			t.Fatal(err)
		}
		updated := server
		updated.Port++
		runner.failOn, runner.failAt, runner.failSeen = "daemon-reload", 1, 0
		if _, err := s.applyOcserv(context.Background(), cfg, updated, true); err == nil {
			t.Fatal("ocserv update failure accepted")
		}
		after, err := os.ReadFile(paths.conf)
		if err != nil || string(after) != string(before) {
			t.Fatalf("ocserv rollback changed config: err=%v", err)
		}
		if err := s.Health(context.Background(), cfg); err != nil {
			t.Fatalf("previous ocserv state not healthy after rollback: %v", err)
		}
	})

	t.Run("ikev2", func(t *testing.T) {
		s, _ := newTestSubsystem(t)
		s.UnitDir = t.TempDir()
		runner := &vpnServiceRunner{active: map[string]bool{}, s: s}
		s.Runner = runner
		cfg, server := ikev2TestConfig()
		if err := s.Apply(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		paths := s.ikev2Paths()
		beforeConf, err := os.ReadFile(paths.conf)
		if err != nil {
			t.Fatal(err)
		}
		beforeCert, err := os.ReadFile(paths.cert)
		if err != nil {
			t.Fatal(err)
		}
		updated := server
		updated.Peers = append([]config.VPNPeer(nil), server.Peers...)
		updated.Peers[0].Credentials = map[string]string{"username": "alice", "password": "new-secret"}
		runner.failOn, runner.failAt, runner.failSeen = "/usr/sbin/swanctl", 2, 0
		if err := s.applyIKEv2(context.Background(), cfg, []config.VPNServer{updated}, true); err == nil {
			t.Fatal("IKEv2 update failure accepted")
		}
		afterConf, confErr := os.ReadFile(paths.conf)
		afterCert, certErr := os.ReadFile(paths.cert)
		if confErr != nil || certErr != nil || string(afterConf) != string(beforeConf) || string(afterCert) != string(beforeCert) {
			t.Fatalf("IKEv2 rollback changed files: conf=%v cert=%v", confErr, certErr)
		}
		if err := s.Health(context.Background(), cfg); err != nil {
			t.Fatalf("previous IKEv2 state not healthy after rollback: %v", err)
		}
	})
}
