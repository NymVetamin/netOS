package netiface

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type netifaceRunnerFunc func(context.Context, string, ...string) (string, error)

func (f netifaceRunnerFunc) Run(ctx context.Context, name string, args ...string) (string, error) {
	return f(ctx, name, args...)
}

type netifaceServiceRunner struct {
	active   map[string]bool
	commands []string
}

func (r *netifaceServiceRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	if name == "systemctl" && len(args) > 1 {
		unit := args[len(args)-1]
		switch args[0] {
		case "is-active":
			if r.active[unit] {
				return "active\n", nil
			}
			return "inactive\n", errors.New("inactive")
		case "restart":
			r.active[unit] = true
		case "disable":
			r.active[unit] = false
		}
	}
	return "", nil
}

func (r *netifaceServiceRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func (f netifaceRunnerFunc) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return f(ctx, name, args...)
}

func TestStaticRouteOwnershipNeverDeletesUnownedNetOSRoutes(t *testing.T) {
	var commands []string
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		commands = append(commands, command)
		return "", nil
	})
	s := NewWAN(runner)
	s.OwnedRoutePath = filepath.Join(t.TempDir(), "owned-wan-routes.json")
	if err := s.syncStaticRouteOwnership(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 0 {
		t.Fatalf("unowned proto-201 routes were queried or deleted: %v", commands)
	}
}

func TestStaticRouteCleanupFailureKeepsOldAndNewOwnership(t *testing.T) {
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		if strings.Contains(command, "route del default") {
			return "", errors.New("route busy")
		}
		if strings.Contains(command, "route show default") {
			return "default via 192.0.2.1 dev old0 proto netos metric 10\n", nil
		}
		return "", nil
	})
	s := NewWAN(runner)
	s.OwnedRoutePath = filepath.Join(t.TempDir(), "owned-wan-routes.json")
	previous := `[{"gateway":"192.0.2.1","interface":"old0","metric":10}]`
	if err := os.WriteFile(s.OwnedRoutePath, []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}
	err := s.syncStaticRouteOwnership(context.Background(), []ownedWANRoute{{Gateway: "198.51.100.1", Interface: "new0", Metric: 20}})
	if err == nil || !strings.Contains(err.Error(), "route busy") {
		t.Fatalf("cleanup failure was hidden: %v", err)
	}
	data, readErr := os.ReadFile(s.OwnedRoutePath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var got []ownedWANRoute
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("route ownership after failure = %#v", got)
	}
}

func TestApplyStaticPreservesUnownedAddresses(t *testing.T) {
	var commands []string
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		commands = append(commands, name+" "+strings.Join(args, " "))
		return "", nil
	})
	w := config.WAN{ID: "wan", Address: "192.0.2.2/24", Gateway: "192.0.2.1", Metric: 10}
	if err := NewWAN(runner).applyStatic(context.Background(), w, "eth0"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(commands, "\n")
	if strings.Contains(joined, "addr del") || strings.Contains(joined, "addr flush") {
		t.Fatalf("static apply removed unowned addresses: %s", joined)
	}
	if !strings.Contains(joined, "addr replace 192.0.2.2/24 dev eth0") {
		t.Fatalf("static address was not applied: %s", joined)
	}
}

func TestNetworkCleanupFailureKeepsOldAndNewOwnership(t *testing.T) {
	newFakeNet(t, "lan")
	path := filepath.Join(t.TempDir(), "owned-network-addresses.json")
	old := []ownedWANAddress{{Interface: "lan", Address: "10.0.0.1/24"}}
	if err := writeOwnedAddresses(path, old); err != nil {
		t.Fatal(err)
	}
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		if strings.Contains(command, "addr show") {
			return "3: lan inet 10.0.0.1/24 scope global lan\n", nil
		}
		if strings.Contains(command, "addr del") {
			return "", errors.New("busy")
		}
		return "", nil
	})
	s := NewNetworks(runner)
	s.OwnedAddressPath = path
	err := s.syncAddressOwnership(context.Background(), []ownedWANAddress{{Interface: "lan", Address: "10.1.0.1/24"}})
	if err == nil {
		t.Fatal("cleanup failure was ignored")
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var got []ownedWANAddress
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("ownership after failure = %#v", got)
	}
}

func TestNetworksHealthRejectsMissingInterface(t *testing.T) {
	newFakeNet(t)
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan-if", Name: "missing0", Type: "bridge", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "lan", Name: "LAN", Interface: "lan-if", RouterAddress: "10.0.0.1/24", Enabled: true}}
	if err := NewNetworks(&linkRunner{}).Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "отсутствует") {
		t.Fatalf("missing network interface health = %v", err)
	}
}

func TestStaleLinkDeleteFailurePreservesOwnership(t *testing.T) {
	newFakeNet(t, "eth0", "br-old:bridge")
	path := ownedFile(t, "br-old")
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		if name == "ip" && strings.Join(args, " ") == "link delete br-old" {
			return "", errors.New("busy")
		}
		return "", nil
	})
	s := &Interfaces{Runner: runner, OwnedPath: path}
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "eth", Name: "eth0", Type: "physical", Enabled: true}}
	if err := s.Apply(context.Background(), cfg); err == nil {
		t.Fatal("stale link deletion failure was ignored")
	}
	if data, err := os.ReadFile(path); err != nil || !strings.Contains(string(data), "br-old") {
		t.Fatalf("ownership was lost: %q, %v", data, err)
	}
}

func TestDHCPScriptPreservesForeignAddressesAndCleansOwnedLease(t *testing.T) {
	script := renderDHCPScript(27)
	for _, want := range []string{
		"STATE=/run/netos-dhcp-$interface.address",
		"ip -4 addr replace \"$ip/$mask\"",
		"ip -4 addr del \"$old\"",
		"ip -4 route flush default",
		"printf '%s\\n' \"$ip/$mask\" > \"$STATE\"",
		"METRIC=27",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("DHCP script lacks %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "addr flush dev") {
		t.Fatalf("DHCP script still flushes foreign addresses:\n%s", script)
	}
	if strings.Contains(script, "%!") {
		t.Fatalf("DHCP script contains a broken fmt directive:\n%s", script)
	}
	if !strings.Contains(dhcpUnit("eth-test", "/tmp/script"), "ExecStopPost=") {
		t.Fatal("DHCP unit does not clean its exact lease on stop")
	}
}

func TestDHCPMetricChangeRestartsActiveClient(t *testing.T) {
	root := t.TempDir()
	oldScripts, oldUnits := dhcpScriptDir, systemdUnitDir
	dhcpScriptDir, systemdUnitDir = filepath.Join(root, "state"), filepath.Join(root, "units")
	t.Cleanup(func() { dhcpScriptDir, systemdUnitDir = oldScripts, oldUnits })
	var commands []string
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		commands = append(commands, command)
		if command == "systemctl is-active netos-dhcp-eth-test.service" {
			return "active\n", nil
		}
		return "", nil
	})
	s := NewWAN(runner)
	if err := s.ensureDHCPClient(context.Background(), config.WAN{Metric: 10}, "eth-test"); err != nil {
		t.Fatal(err)
	}
	commands = nil
	if err := s.ensureDHCPClient(context.Background(), config.WAN{Metric: 20}, "eth-test"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(commands, "\n"), "systemctl restart netos-dhcp-eth-test.service") {
		t.Fatalf("metric change did not restart DHCP: %v", commands)
	}
}

func TestWANHealthRequiresRouteForTheSameStaticUplink(t *testing.T) {
	newFakeNet(t, "eth0")
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(command, "addr show dev eth0"):
			return "2: eth0 inet 192.0.2.2/24 scope global eth0\n", nil
		case strings.Contains(command, "route show default"):
			return "default via 198.51.100.1 dev eth1 proto netos metric 10\n", nil
		}
		return "", nil
	})
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "wan-if", Name: "eth0", Type: "physical", Enabled: true}}
	cfg.WANs = []config.WAN{{ID: "wan", Name: "WAN", Interface: "wan-if", Enabled: true, Proto: "static", Address: "192.0.2.2/24", Gateway: "192.0.2.1", Metric: 10}}
	if err := NewWAN(runner).Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "точного default") {
		t.Fatalf("unrelated default route passed static WAN health: %v", err)
	}
}

func TestWANHealthChecksDHCPAndL2TPUnits(t *testing.T) {
	newFakeNet(t, "eth0")
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		if strings.Contains(command, "route show default") {
			return "default via 192.0.2.1 dev eth0 proto dhcp metric 10\n", nil
		}
		if strings.Contains(command, "addr show dev eth0") {
			return "2: eth0 inet 192.0.2.2/24 scope global eth0\n", nil
		}
		if strings.HasPrefix(command, "systemctl is-active") {
			return "inactive\n", errors.New("inactive")
		}
		return "", nil
	})
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "wan-if", Name: "eth0", Type: "physical", Enabled: true}}
	cfg.WANs = []config.WAN{{ID: "wan", Name: "DHCP", Interface: "wan-if", Enabled: true, Proto: "dhcp", Metric: 10}}
	if err := NewWAN(runner).Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "DHCP-клиент") {
		t.Fatalf("inactive DHCP unit passed health: %v", err)
	}
	cfg.WANs[0] = config.WAN{ID: "wan", Name: "L2TP", Interface: "wan-if", Enabled: true, Proto: "l2tp", Underlay: "static", Address: "192.0.2.2/24", Metric: 10}
	if err := NewWAN(runner).Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "L2TP") {
		t.Fatalf("inactive L2TP unit passed health: %v", err)
	}
}

func TestInterfaceHealthChecksVLANStateMTUAndMAC(t *testing.T) {
	newFakeNet(t, "eth0", "eth0.7:vlan:7:eth0")
	runner := netifaceRunnerFunc(func(_ context.Context, _ string, _ ...string) (string, error) {
		return "3: eth0.7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1400 state UP link/ether 02:00:00:00:00:07 brd ff:ff:ff:ff:ff:ff\n", nil
	})
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{
		{ID: "parent", Name: "eth0", Type: "physical", Enabled: true},
		{ID: "vlan", Name: "eth0.7", Type: "vlan", Parent: "parent", VLANID: 7, MTU: 1400, MAC: "02:00:00:00:00:07", Enabled: true},
	}
	// The runner output is intentionally shared; check the VLAN in isolation
	// so the physical port's real properties do not affect this assertion.
	cfg.Interfaces = cfg.Interfaces[1:]
	cfg.Interfaces[0].Parent = ""
	if err := (&Interfaces{Runner: runner}).Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Interfaces[0].MTU = 1500
	if err := (&Interfaces{Runner: runner}).Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "MTU") {
		t.Fatalf("wrong MTU passed interface health: %v", err)
	}
	cfg.Interfaces[0].MTU = 1400
	cfg.Interfaces[0].MAC = "02:00:00:00:00:08"
	if err := (&Interfaces{Runner: runner}).Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "MAC") {
		t.Fatalf("wrong MAC passed interface health: %v", err)
	}
}

func TestParseLinkStateDoesNotMistakeLowerUpForAdministrativeUp(t *testing.T) {
	up, mtu, mac := parseLinkState("2: eth0: <BROADCAST,LOWER_UP> mtu 1500 link/ether aa:bb:cc:dd:ee:ff")
	if up || mtu != 1500 || mac != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("parseLinkState = %v %d %q", up, mtu, mac)
	}
}

func TestClientCleanupFailureKeepsArtifacts(t *testing.T) {
	root := t.TempDir()
	oldScripts, oldUnits, oldConfs := dhcpScriptDir, systemdUnitDir, pppoeConfDir
	dhcpScriptDir = filepath.Join(root, "state")
	pppoeConfDir = dhcpScriptDir
	systemdUnitDir = filepath.Join(root, "units")
	t.Cleanup(func() { dhcpScriptDir, systemdUnitDir, pppoeConfDir = oldScripts, oldUnits, oldConfs })
	for _, dir := range []string{dhcpScriptDir, systemdUnitDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		if strings.HasPrefix(command, "systemctl disable --now") {
			return "", errors.New("stop failed")
		}
		if strings.HasPrefix(command, "systemctl is-active") {
			return "active\n", nil
		}
		return "", nil
	})
	s := NewWAN(runner)

	dhcpUnitPath := filepath.Join(systemdUnitDir, "netos-dhcp-eth-test.service")
	if err := os.WriteFile(dhcpUnitPath, []byte("unit"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.cleanupDHCPClients(context.Background(), map[string]bool{}); err == nil {
		t.Fatal("active DHCP unit cleanup succeeded")
	}
	if _, err := os.Stat(dhcpUnitPath); err != nil {
		t.Fatalf("DHCP artifact lost after failed stop: %v", err)
	}

	pppoeUnitPath := filepath.Join(systemdUnitDir, pppoeUnitName("test"))
	if err := os.WriteFile(pppoeUnitPath, []byte("unit"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.cleanupPPPoE(context.Background(), map[string]bool{}); err == nil {
		t.Fatal("active PPPoE unit cleanup succeeded")
	}
	if _, err := os.Stat(pppoeUnitPath); err != nil {
		t.Fatalf("PPPoE artifact lost after failed stop: %v", err)
	}

	l2tpUnitPath := filepath.Join(systemdUnitDir, l2tpUnitName("test"))
	if err := os.WriteFile(l2tpUnitPath, []byte("unit"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.cleanupL2TP(context.Background(), map[string]bool{}); err == nil {
		t.Fatal("active L2TP unit cleanup succeeded")
	}
	if _, err := os.Stat(l2tpUnitPath); err != nil {
		t.Fatalf("L2TP artifact lost after failed stop: %v", err)
	}
}

func TestCleanupRemovesOrphanClientConfigsWithoutUnits(t *testing.T) {
	root := t.TempDir()
	oldScripts, oldUnits, oldConfs := dhcpScriptDir, systemdUnitDir, pppoeConfDir
	dhcpScriptDir = filepath.Join(root, "state")
	pppoeConfDir = dhcpScriptDir
	systemdUnitDir = filepath.Join(root, "units")
	t.Cleanup(func() { dhcpScriptDir, systemdUnitDir, pppoeConfDir = oldScripts, oldUnits, oldConfs })
	for _, dir := range []string{dhcpScriptDir, systemdUnitDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	paths := []string{
		filepath.Join(dhcpScriptDir, "udhcpc-old.sh"),
		filepath.Join(pppoeConfDir, "pppoe-old.conf"),
		filepath.Join(pppoeConfDir, "l2tp-old.conf"),
		filepath.Join(pppoeConfDir, "l2tp-old.ppp"),
	}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("orphan"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := NewWAN(&linkRunner{})
	if err := s.cleanupDHCPClients(context.Background(), map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if err := s.cleanupPPPoE(context.Background(), map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if err := s.cleanupL2TP(context.Background(), map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("orphan %s remains: %v", path, err)
		}
	}
}

func TestLNSRouteOwnershipDeletesOnlyConfirmedStaleRoute(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned-l2tp-routes.json")
	item := ownedLNSRoute{Destination: "203.0.113.7/32", Gateway: "192.0.2.1", Interface: "eth0"}
	var commands []string
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		commands = append(commands, name+" "+strings.Join(args, " "))
		return "", nil
	})
	s := NewWAN(runner)
	s.OwnedLNSRoutePath = path
	if err := s.writeOwnedLNSRoutes([]ownedLNSRoute{item}); err != nil {
		t.Fatal(err)
	}
	s.lnsRouteWanted = map[string]ownedLNSRoute{}
	if err := s.syncLNSRouteOwnership(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(commands, "\n"), "ip -4 route del 203.0.113.7/32 via 192.0.2.1 dev eth0") {
		t.Fatalf("stale LNS route was not deleted exactly: %v", commands)
	}
	items, err := s.readOwnedLNSRoutes()
	if err != nil || len(items) != 0 {
		t.Fatalf("LNS ownership after cleanup = %#v, %v", items, err)
	}
}

func TestLNSRouteDeleteFailurePreservesOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned-l2tp-routes.json")
	item := ownedLNSRoute{Destination: "203.0.113.7/32", Gateway: "192.0.2.1", Interface: "eth0"}
	runner := netifaceRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		if strings.Contains(command, "route del") {
			return "", errors.New("busy")
		}
		if strings.Contains(command, "route show") {
			return "203.0.113.7 via 192.0.2.1 dev eth0 proto netos\n", nil
		}
		return "", nil
	})
	s := NewWAN(runner)
	s.OwnedLNSRoutePath = path
	if err := s.writeOwnedLNSRoutes([]ownedLNSRoute{item}); err != nil {
		t.Fatal(err)
	}
	s.lnsRouteWanted = map[string]ownedLNSRoute{}
	if err := s.syncLNSRouteOwnership(context.Background()); err == nil {
		t.Fatal("failed LNS route deletion was accepted")
	}
	items, err := s.readOwnedLNSRoutes()
	if err != nil || len(items) != 1 || lnsRouteKey(items[0]) != lnsRouteKey(item) {
		t.Fatalf("LNS ownership was lost: %#v, %v", items, err)
	}
}

func TestPPPoEFakeServiceLifecycleIsIdempotentAndCleans(t *testing.T) {
	root := t.TempDir()
	oldUnits, oldConfs := systemdUnitDir, pppoeConfDir
	systemdUnitDir, pppoeConfDir = filepath.Join(root, "units"), filepath.Join(root, "state")
	t.Cleanup(func() { systemdUnitDir, pppoeConfDir = oldUnits, oldConfs })
	runner := &netifaceServiceRunner{active: map[string]bool{}}
	s := NewWAN(runner)
	w := config.WAN{ID: "fake", Name: "Fake PPPoE", Proto: "pppoe", Username: "user", Password: "secret", Metric: 20}
	cfg := config.Default()
	cfg.WANs = []config.WAN{w}
	if err := s.ensurePPPoE(context.Background(), w, "eth-test"); err != nil {
		t.Fatal(err)
	}
	unit := pppoeUnitName(w.ID)
	if !runner.active[unit] {
		t.Fatal("PPPoE unit was not started")
	}
	runner.commands = nil
	if err := s.ensurePPPoE(context.Background(), w, "eth-test"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(runner.commands, "\n"), "systemctl restart "+unit) {
		t.Fatalf("idempotent PPPoE apply restarted service: %v", runner.commands)
	}
	if err := s.cleanupPPPoE(context.Background(), map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if runner.active[unit] {
		t.Fatal("PPPoE unit remains active")
	}
	if _, err := os.Stat(pppoeConfPath(w.ID)); !os.IsNotExist(err) {
		t.Fatalf("PPPoE config remains: %v", err)
	}
}

func TestL2TPFakeServiceLifecycleIsIdempotentAndCleans(t *testing.T) {
	root := t.TempDir()
	oldUnits, oldConfs := systemdUnitDir, pppoeConfDir
	systemdUnitDir, pppoeConfDir = filepath.Join(root, "units"), filepath.Join(root, "state")
	t.Cleanup(func() { systemdUnitDir, pppoeConfDir = oldUnits, oldConfs })
	runner := &netifaceServiceRunner{active: map[string]bool{}}
	s := NewWAN(runner)
	s.OwnedLNSRoutePath = filepath.Join(root, "owned-lns.json")
	s.lnsRouteWanted = map[string]ownedLNSRoute{}
	w := config.WAN{ID: "fake", Name: "Fake L2TP", Proto: "l2tp", Server: "203.0.113.7", Underlay: "static", Gateway: "192.0.2.1", Username: "user", Password: "secret", Metric: 30}
	cfg := config.Default()
	cfg.WANs = []config.WAN{w}
	if err := s.ensureL2TP(context.Background(), w, "eth-test"); err != nil {
		t.Fatal(err)
	}
	unit := l2tpUnitName(w.ID)
	if !runner.active[unit] {
		t.Fatal("L2TP unit was not started")
	}
	runner.commands = nil
	if err := s.ensureL2TP(context.Background(), w, "eth-test"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(runner.commands, "\n"), "systemctl restart "+unit) {
		t.Fatalf("idempotent L2TP apply restarted service: %v", runner.commands)
	}
	if err := s.cleanupL2TP(context.Background(), map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	s.lnsRouteWanted = map[string]ownedLNSRoute{}
	if err := s.syncLNSRouteOwnership(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.active[unit] {
		t.Fatal("L2TP unit remains active")
	}
	for _, path := range []string{l2tpConfPath(w.ID), l2tpPPPPath(w.ID)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("L2TP artifact remains at %s: %v", path, err)
		}
	}
}
