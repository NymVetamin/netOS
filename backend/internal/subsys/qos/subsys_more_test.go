package qos

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

func clientLimitConfig() *config.Config {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "lan0", Type: "bridge", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "home", Interface: "lan", Enabled: true}}
	cfg.Clients = []config.Client{{ID: "phone", MAC: "aa:bb:cc:dd:ee:ff", Network: "home", DownKbit: 5000, UpKbit: 1000}}
	return cfg
}

func TestIdentityAndPlanEveryTransition(t *testing.T) {
	runner := &fakeRunner{links: map[string]bool{}}
	s := New(runner, t.TempDir())
	if s.Name() != "qos" {
		t.Fatalf("name=%q", s.Name())
	}
	empty := config.Default()
	if actions, err := s.Plan(nil, empty); err != nil || len(actions) != 0 {
		t.Fatalf("empty initial plan=%+v err=%v", actions, err)
	}

	enabled := testConfig("dhcp")
	actions, err := s.Plan(empty, enabled)
	if err != nil || len(actions) != 1 || actions[0].Kind != "create" || actions[0].Target != "очереди трафика" {
		t.Fatalf("enable plan=%+v err=%v", actions, err)
	}
	actions, err = s.Plan(enabled, empty)
	if err != nil || len(actions) != 1 || actions[0].Kind != "delete" {
		t.Fatalf("disable plan=%+v err=%v", actions, err)
	}

	clients := clientLimitConfig()
	actions, err = s.Plan(empty, clients)
	if err != nil || len(actions) != 1 || actions[0].Kind != "create" || actions[0].Target != "лимиты клиентов" {
		t.Fatalf("client create plan=%+v err=%v", actions, err)
	}
	actions, err = s.Plan(clients, empty)
	if err != nil || len(actions) != 1 || actions[0].Kind != "delete" || actions[0].Target != "лимиты клиентов" {
		t.Fatalf("client delete plan=%+v err=%v", actions, err)
	}

	changed := *enabled
	changed.QoS.WANs = append([]config.QoSWAN(nil), enabled.QoS.WANs...)
	changed.QoS.WANs[0].UploadKbit++
	changed.Clients = clients.Clients
	actions, err = s.Plan(enabled, &changed)
	if err != nil || len(actions) != 2 || actions[0].Kind != "update" || actions[1].Target != "лимиты клиентов" {
		t.Fatalf("combined plan=%+v err=%v", actions, err)
	}

	if !equalQoS(config.QoS{Enabled: true, WANs: []config.QoSWAN{{WAN: "b", Diffserv: ""}, {WAN: "a", Diffserv: "diffserv3"}}}, config.QoS{Enabled: true, WANs: []config.QoSWAN{{WAN: "a", Diffserv: "diffserv3"}, {WAN: "b", Diffserv: "diffserv4"}}}) {
		t.Fatal("runtime-equivalent QoS order/default profile treated as a change")
	}
	leftClients := []config.Client{{MAC: "AA:BB:CC:DD:EE:FF", Network: "home", DownKbit: 1000, Name: "old"}}
	rightClients := []config.Client{{MAC: "aa:bb:cc:dd:ee:ff", Network: "home", DownKbit: 1000, Name: "renamed", Comment: "metadata"}}
	if !equalClientLimits(leftClients, rightClients) {
		t.Fatal("client metadata or MAC spelling treated as a QoS change")
	}
	ordered := []config.Client{
		{MAC: "00:00:00:00:00:02", Network: "b", UpKbit: 1000},
		{MAC: "00:00:00:00:00:01", Network: "a", DownKbit: 2000},
		{MAC: "00:00:00:00:00:03", Network: "a"},
	}
	reordered := []config.Client{ordered[2], ordered[1], ordered[0]}
	if !equalClientLimits(ordered, reordered) {
		t.Fatal("client order or zero-limit metadata treated as a QoS change")
	}
}

func TestPlanReportsLiveDriftAndApplyIsExactNoOp(t *testing.T) {
	runner := &fakeRunner{links: map[string]bool{"eth9": true}}
	dir := t.TempDir()
	s := New(runner, dir)
	cfg := testConfig("dhcp")
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	ownedPath := filepath.Join(dir, "owned-qos.json")
	before, err := os.Stat(ownedPath)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	runner.commands = nil
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	for _, command := range runner.commands {
		if strings.Contains(command, " replace ") || strings.Contains(command, " add ") || strings.Contains(command, " del ") {
			t.Fatalf("clean Apply mutated runtime: %s", command)
		}
	}
	after, _ := os.Stat(ownedPath)
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("clean Apply rewrote ownership: %v -> %v", before.ModTime(), after.ModTime())
	}

	runner.outputs = map[string]string{
		"tc qdisc show dev eth9": "qdisc cake 8001: root bandwidth 1234Kbit diffserv4 nat\nqdisc ingress ffff: parent ffff:fff1",
	}
	actions, err := s.Plan(cfg, cfg)
	if err != nil || len(actions) != 1 || !strings.Contains(actions[0].Detail, "расхождения") {
		t.Fatalf("drift plan=%+v err=%v", actions, err)
	}
}

func TestHealthChecksWANRateProfileIngressRedirectAndOwnership(t *testing.T) {
	cases := []struct {
		name    string
		command string
		output  string
	}{
		{"upload rate", "tc qdisc show dev eth9", "qdisc cake 1: root bandwidth 9499Kbit diffserv4 nat\nqdisc ingress ffff:"},
		{"profile", "tc qdisc show dev eth9", "qdisc cake 1: root bandwidth 9500Kbit besteffort nat\nqdisc ingress ffff:"},
		{"ingress", "tc qdisc show dev eth9", "qdisc cake 1: root bandwidth 9500Kbit diffserv4 nat"},
		{"redirect", "tc filter show dev eth9 parent ffff:", "filter pref 1 u32 mirred redirect dev wrong0"},
		{"download", "tc qdisc show dev ifb-netos-3", "qdisc cake 2: root bandwidth 47000Kbit diffserv4 nat wash ingress"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			runner := &fakeRunner{links: map[string]bool{"eth9": true}}
			s := New(runner, t.TempDir())
			cfg := testConfig("dhcp")
			if err := s.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			runner.outputs = map[string]string{tt.command: tt.output}
			if err := s.Health(context.Background(), cfg); err == nil {
				t.Fatal("health accepted WAN drift")
			}
		})
	}

	runner := &fakeRunner{links: map[string]bool{"eth9": true}}
	dir := t.TempDir()
	s := New(runner, dir)
	cfg := testConfig("dhcp")
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "owned-qos.json"), []byte("[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "принадлежащих") {
		t.Fatalf("ownership drift accepted: %v", err)
	}
}

func TestHealthChecksEveryClientRateMACAndOwnership(t *testing.T) {
	cases := []struct {
		name    string
		command string
		output  string
	}{
		{"download rate", "tc class show dev lan0", "class htb 1:10 parent 1:1 rate 4999kbit ceil 4999kbit"},
		{"download mac", "tc filter show dev lan0 parent 1:", "filter protocol all pref 100 flower dst_mac 00:11:22:33:44:55 classid 1:10"},
		{"upload rate", "tc filter show dev lan0 parent ffff:", "filter protocol all pref 100 flower src_mac aa:bb:cc:dd:ee:ff action police rate 999kbit"},
		{"extra download filter", "tc filter show dev lan0 parent 1:", "filter protocol all pref 100 flower dst_mac aa:bb:cc:dd:ee:ff classid 1:10\nfilter protocol all pref 101 flower dst_mac 00:11:22:33:44:55 classid 1:11"},
		{"extra upload filter", "tc filter show dev lan0 parent ffff:", "filter protocol all pref 100 flower src_mac aa:bb:cc:dd:ee:ff action police rate 1Mbit\nfilter protocol all pref 101 flower src_mac 00:11:22:33:44:55 action police rate 2Mbit"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			runner := &fakeRunner{links: map[string]bool{"lan0": true}}
			s := New(runner, t.TempDir())
			cfg := clientLimitConfig()
			if err := s.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			runner.outputs = map[string]string{tt.command: tt.output}
			if err := s.Health(context.Background(), cfg); err == nil {
				t.Fatal("health accepted client drift")
			}
		})
	}
}

func TestCleanupFailurePreservesOwnershipAndMissingObjectsAreAccepted(t *testing.T) {
	runner := &fakeRunner{links: map[string]bool{"eth9": true}}
	dir := t.TempDir()
	s := New(runner, dir)
	cfg := testConfig("dhcp")
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	runner.errors = map[string]error{"tc qdisc del dev eth9 root": errors.New("permission denied")}
	cfg.QoS.Enabled = false
	if err := s.Apply(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("cleanup error ignored: %v", err)
	}
	owned, err := s.readOwned()
	if err != nil || len(owned) != 1 {
		t.Fatalf("ownership lost after cleanup failure: %+v err=%v", owned, err)
	}
	runner.errors["tc qdisc del dev eth9 root"] = errors.New("Cannot find qdisc")
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("missing qdisc must be idempotent: %v", err)
	}
}

func TestFailedNewWANApplyCleansCreatedIFB(t *testing.T) {
	runner := &fakeRunner{links: map[string]bool{"eth9": true}}
	command := "tc qdisc replace dev eth9 root cake bandwidth 9500kbit diffserv4 nat"
	runner.errors = map[string]error{command: errors.New("cake unavailable")}
	s := New(runner, t.TempDir())
	err := s.Apply(context.Background(), testConfig("dhcp"))
	if err == nil || !strings.Contains(err.Error(), "cake unavailable") {
		t.Fatalf("apply error=%v", err)
	}
	if runner.links["ifb-netos-3"] {
		t.Fatal("new IFB leaked after failed apply")
	}
	owned, readErr := s.readOwned()
	if readErr != nil || len(owned) != 0 {
		t.Fatalf("failed apply recorded ownership: %+v err=%v", owned, readErr)
	}
}

func TestClientTargetPreflightHappensBeforeOldCleanup(t *testing.T) {
	runner := &fakeRunner{links: map[string]bool{"lan0": true}}
	s := New(runner, t.TempDir())
	old := clientLimitConfig()
	if err := s.Apply(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	next := clientLimitConfig()
	next.Interfaces[0].Name = "lan-missing"
	runner.commands = nil
	err := s.Apply(context.Background(), next)
	if err == nil || !strings.Contains(err.Error(), "lan-missing") {
		t.Fatalf("missing target error=%v", err)
	}
	for _, command := range runner.commands {
		if strings.Contains(command, "qdisc del dev lan0") {
			t.Fatalf("old working limits removed before target preflight: %s", command)
		}
	}
}

func TestCleanupVerifiesObjectsActuallyDisappeared(t *testing.T) {
	runner := &fakeRunner{links: map[string]bool{"eth9": true}}
	dir := t.TempDir()
	s := New(runner, dir)
	cfg := testConfig("dhcp")
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	runner.outputs = map[string]string{
		"tc qdisc show dev eth9": "qdisc cake 1: root bandwidth 9.5Mbit diffserv4 nat",
	}
	cfg.QoS.Enabled = false
	if err := s.Apply(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "остались") {
		t.Fatalf("residual qdisc accepted: %v", err)
	}
	owned, _ := s.readOwned()
	if len(owned) != 1 {
		t.Fatalf("ownership lost with residual qdisc: %+v", owned)
	}

	runner.outputs = map[string]string{
		"tc qdisc show dev eth9":       "",
		"ip link show dev ifb-netos-3": "still present",
	}
	if err := s.Apply(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "ifb-netos-3") {
		t.Fatalf("residual IFB accepted: %v", err)
	}
}

func TestDesiredMappingsAndErrors(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "b", Name: "eth2"}, {ID: "a", Name: "eth1"}}
	cfg.WANs = []config.WAN{
		{ID: "z", Index: 7, Interface: "a", Proto: "l2tp"},
		{ID: "a", Index: 2, Interface: "b", Proto: "static"},
	}
	cfg.QoS.WANs = []config.QoSWAN{{WAN: "z"}, {WAN: "a"}}
	links, err := desiredLinks(cfg)
	if err != nil || len(links) != 2 || links[0].WAN != "a" || links[0].Interface != "eth2" || links[1].Interface != "ppp-z" {
		t.Fatalf("links=%+v err=%v", links, err)
	}
	cfg.QoS.WANs = []config.QoSWAN{{WAN: "missing"}}
	if _, err := desiredLinks(cfg); err == nil || !strings.Contains(err.Error(), "не найден") {
		t.Fatalf("missing WAN accepted: %v", err)
	}
	cfg.WANs = []config.WAN{{ID: "bad", Interface: "missing", Proto: "dhcp"}}
	cfg.QoS.WANs = []config.QoSWAN{{WAN: "bad"}}
	if _, err := desiredLinks(cfg); err == nil || !strings.Contains(err.Error(), "нет системного") {
		t.Fatalf("missing interface accepted: %v", err)
	}

	clients := clientLimitConfig()
	clients.Clients = append(clients.Clients,
		config.Client{ID: "zero", MAC: "00:00:00:00:00:01", Network: "home"},
		config.Client{ID: "upload", MAC: "00:00:00:00:00:02", Network: "home", UpKbit: 2000},
		config.Client{ID: "download", MAC: "00:00:00:00:00:00", Network: "home", DownKbit: 3000},
	)
	items, err := desiredClientInterfaces(clients)
	if err != nil || len(items) != 1 || len(items[0].Download) != 2 || len(items[0].Upload) != 2 || items[0].Download[0].MAC != "00:00:00:00:00:00" {
		t.Fatalf("client interfaces=%+v err=%v", items, err)
	}
	clients.Clients[0].Network = "missing"
	if _, err := desiredClientInterfaces(clients); err == nil || !strings.Contains(err.Error(), "не найден") {
		t.Fatalf("missing client network accepted: %v", err)
	}
}

func TestEveryApplyLinkCommandFailureIsReturned(t *testing.T) {
	item := ownedLink{WAN: "wan1", Interface: "eth9", IFB: "ifb-netos-3"}
	setting := config.QoSWAN{WAN: "wan1", UploadKbit: 9500, DownloadKbit: 47500, Diffserv: ""}
	commands := []struct {
		command string
		owned   bool
	}{
		{"ip link add name ifb-netos-3 type ifb", false},
		{"ip link set dev ifb-netos-3 up", true},
		{"tc qdisc replace dev eth9 root cake bandwidth 9500kbit diffserv4 nat", true},
		{"tc qdisc replace dev eth9 handle ffff: ingress", true},
		{"tc filter replace dev eth9 parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev ifb-netos-3", true},
		{"tc qdisc replace dev ifb-netos-3 root cake bandwidth 47500kbit diffserv4 nat wash ingress", true},
	}
	for _, tt := range commands {
		t.Run(tt.command, func(t *testing.T) {
			runner := &fakeRunner{links: map[string]bool{"eth9": true, "ifb-netos-3": tt.owned}, errors: map[string]error{tt.command: errors.New("injected")}}
			err := New(runner, t.TempDir()).applyLink(context.Background(), item, setting, tt.owned)
			if err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestEveryClientCommandFailureIsReturned(t *testing.T) {
	client := config.Client{MAC: "aa:bb:cc:dd:ee:ff", DownKbit: 5000, UpKbit: 1000}
	item := clientInterface{Name: "lan0", Download: []config.Client{client}, Upload: []config.Client{client}}
	commands := []string{
		"tc qdisc del dev lan0 root",
		"tc qdisc replace dev lan0 root handle 1: htb default 1",
		"tc class replace dev lan0 parent 1: classid 1:1 htb rate 10gbit ceil 10gbit",
		"tc class replace dev lan0 parent 1:1 classid 1:10 htb rate 5000kbit ceil 5000kbit burst 32k",
		"tc filter replace dev lan0 parent 1: protocol all pref 100 flower dst_mac aa:bb:cc:dd:ee:ff classid 1:10",
		"tc qdisc del dev lan0 ingress",
		"tc qdisc replace dev lan0 handle ffff: ingress",
		"tc filter replace dev lan0 parent ffff: protocol all pref 100 flower src_mac aa:bb:cc:dd:ee:ff action police rate 1000kbit burst 64k conform-exceed drop",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			runner := &fakeRunner{links: map[string]bool{"lan0": true}, errors: map[string]error{command: errors.New("injected")}}
			if err := New(runner, t.TempDir()).applyClientInterface(context.Background(), item); err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("error=%v", err)
			}
		})
	}

	runner := &fakeRunner{links: map[string]bool{"lan0": true}}
	if err := New(runner, t.TempDir()).applyClientInterface(context.Background(), clientInterface{Name: "lan0"}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "qdisc del dev lan0 root") || !strings.Contains(joined, "qdisc del dev lan0 ingress") {
		t.Fatalf("zero-limit cleanup missing:\n%s", joined)
	}
}

func TestMalformedOwnershipFilesAreRejected(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"owned-qos.json", "owned-qos-clients.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := New(&fakeRunner{links: map[string]bool{}}, dir)
	if _, err := s.readOwned(); err == nil || !strings.Contains(err.Error(), "разбор") {
		t.Fatalf("malformed WAN ownership accepted: %v", err)
	}
	if _, err := s.readClientInterfaces(); err == nil {
		t.Fatal("malformed client ownership accepted")
	}
}

func TestDoubleFailureRecordsLeakedObjectsForRetry(t *testing.T) {
	t.Run("WAN", func(t *testing.T) {
		runner := &fakeRunner{links: map[string]bool{"eth9": true}, errors: map[string]error{
			"tc qdisc replace dev eth9 root cake bandwidth 9500kbit diffserv4 nat": errors.New("apply failed"),
			"tc qdisc del dev eth9 root": errors.New("cleanup failed"),
		}}
		s := New(runner, t.TempDir())
		err := s.Apply(context.Background(), testConfig("dhcp"))
		if err == nil || !strings.Contains(err.Error(), "apply failed") || !strings.Contains(err.Error(), "cleanup failed") {
			t.Fatalf("double failure=%v", err)
		}
		owned, readErr := s.readOwned()
		if readErr != nil || len(owned) != 1 || owned[0].IFB != "ifb-netos-3" {
			t.Fatalf("leaked WAN object not recorded: %+v err=%v", owned, readErr)
		}
	})

	t.Run("client", func(t *testing.T) {
		runner := &fakeRunner{links: map[string]bool{"lan0": true}, errors: map[string]error{
			"tc class replace dev lan0 parent 1: classid 1:1 htb rate 10gbit ceil 10gbit": errors.New("apply failed"),
		}, outputs: map[string]string{
			"tc qdisc show dev lan0": "qdisc htb 1: root default 1",
		}}
		s := New(runner, t.TempDir())
		err := s.Apply(context.Background(), clientLimitConfig())
		if err == nil || !strings.Contains(err.Error(), "apply failed") || !strings.Contains(err.Error(), "остались") {
			t.Fatalf("double failure=%v", err)
		}
		owned, readErr := s.readClientInterfaces()
		if readErr != nil || len(owned) != 1 || owned[0] != "lan0" {
			t.Fatalf("leaked client object not recorded: %+v err=%v", owned, readErr)
		}
	})
}

func TestApplyReconcilesExistingAndStaleOwnedLinks(t *testing.T) {
	runner := &fakeRunner{links: map[string]bool{"eth9": true, "eth10": true}}
	dir := t.TempDir()
	s := New(runner, dir)
	old := testConfig("dhcp")
	if err := s.Apply(context.Background(), old); err != nil {
		t.Fatal(err)
	}

	// Runtime drift on the same owned IFB must be repaired without a second link add.
	runner.outputs = map[string]string{"tc qdisc show dev eth9": "qdisc cake 1: root bandwidth 1Kbit besteffort nat"}
	runner.commands = nil
	if err := s.Apply(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(runner.commands, "\n"), "ip link add name ifb-netos-3") {
		t.Fatal("owned IFB was recreated during drift repair")
	}

	// Replacing the WAN must remove the old owned queue and IFB before recording the new one.
	runner.outputs = nil
	next := testConfig("dhcp")
	next.Interfaces[0] = config.Interface{ID: "uplink2", Name: "eth10", Enabled: true, Type: "physical"}
	next.WANs[0] = config.WAN{ID: "wan2", Index: 4, Interface: "uplink2", Enabled: true, Proto: "dhcp"}
	next.QoS.WANs[0].WAN = "wan2"
	runner.commands = nil
	if err := s.Apply(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "ip link del dev ifb-netos-3") || !strings.Contains(joined, "ip link add name ifb-netos-4 type ifb") {
		t.Fatalf("stale/new reconciliation incomplete:\n%s", joined)
	}
}

func TestApplyPreflightRejectsMissingWANBeforeMutation(t *testing.T) {
	runner := &fakeRunner{links: map[string]bool{}}
	s := New(runner, t.TempDir())
	err := s.Apply(context.Background(), testConfig("dhcp"))
	if err == nil || !strings.Contains(err.Error(), "eth9") {
		t.Fatalf("missing WAN target error=%v", err)
	}
	for _, command := range runner.commands {
		if strings.HasPrefix(command, "tc ") || strings.Contains(command, "link add") {
			t.Fatalf("runtime mutated before WAN preflight completed: %s", command)
		}
	}
}

func TestOwnershipWriteFailureCleansNewRuntimeObjects(t *testing.T) {
	t.Run("WAN", func(t *testing.T) {
		runner := &fakeRunner{links: map[string]bool{"eth9": true}}
		s := New(runner, t.TempDir())
		s.writeFile = func(string, []byte, os.FileMode) error { return errors.New("injected ownership write failure") }
		err := s.Apply(context.Background(), testConfig("dhcp"))
		if err == nil {
			t.Fatal("ownership write failure accepted")
		}
		if runner.links["ifb-netos-3"] {
			t.Fatal("new IFB leaked after ownership write failure")
		}
	})

	t.Run("client", func(t *testing.T) {
		runner := &fakeRunner{links: map[string]bool{"lan0": true}}
		s := New(runner, t.TempDir())
		s.writeFile = func(string, []byte, os.FileMode) error { return errors.New("injected ownership write failure") }
		err := s.applyClients(context.Background(), clientLimitConfig())
		if err == nil {
			t.Fatal("client ownership write failure accepted")
		}
		if !runner.cleaned["lan0"] {
			t.Fatal("new client qdisc was not cleaned after ownership write failure")
		}
	})
}

func TestHealthReadAndCommandErrorsArePropagated(t *testing.T) {
	t.Run("WAN ownership", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "owned-qos.json"), 0o700); err != nil {
			t.Fatal(err)
		}
		err := New(&fakeRunner{links: map[string]bool{}}, dir).Health(context.Background(), config.Default())
		if err == nil {
			t.Fatal("WAN ownership read error ignored")
		}
	})

	t.Run("client ownership", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "owned-qos-clients.json"), 0o700); err != nil {
			t.Fatal(err)
		}
		err := New(&fakeRunner{links: map[string]bool{}}, dir).healthClients(context.Background(), config.Default())
		if err == nil {
			t.Fatal("client ownership read error ignored")
		}
	})

	wanCommands := []string{
		"tc qdisc show dev eth9",
		"tc filter show dev eth9 parent ffff:",
		"tc qdisc show dev ifb-netos-3",
	}
	for _, command := range wanCommands {
		t.Run(command, func(t *testing.T) {
			runner := &fakeRunner{links: map[string]bool{"eth9": true}}
			s := New(runner, t.TempDir())
			cfg := testConfig("dhcp")
			if err := s.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			runner.errors = map[string]error{command: errors.New("read failed")}
			if err := s.Health(context.Background(), cfg); err == nil {
				t.Fatalf("command error ignored: %s", command)
			}
		})
	}

	clientCommands := []string{
		"tc qdisc show dev lan0",
		"tc class show dev lan0",
		"tc filter show dev lan0 parent 1:",
		"tc filter show dev lan0 parent ffff:",
	}
	for _, command := range clientCommands {
		t.Run(command, func(t *testing.T) {
			runner := &fakeRunner{links: map[string]bool{"lan0": true}}
			s := New(runner, t.TempDir())
			cfg := clientLimitConfig()
			if err := s.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			runner.errors = map[string]error{command: errors.New("read failed")}
			if err := s.Health(context.Background(), cfg); err == nil {
				t.Fatalf("command error ignored: %s", command)
			}
		})
	}
}

func TestHealthRejectsMissingAndUnexpectedClientQdiscs(t *testing.T) {
	cases := []struct {
		name   string
		client config.Client
		qdisc  string
	}{
		{"missing download", config.Client{DownKbit: 5000}, "qdisc ingress ffff:"},
		{"unexpected download", config.Client{UpKbit: 1000}, "qdisc htb 1: root\nqdisc ingress ffff:"},
		{"missing upload", config.Client{UpKbit: 1000}, ""},
		{"unexpected upload", config.Client{DownKbit: 5000}, "qdisc htb 1: root\nqdisc ingress ffff:"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := clientLimitConfig()
			cfg.Clients[0].DownKbit = tt.client.DownKbit
			cfg.Clients[0].UpKbit = tt.client.UpKbit
			runner := &fakeRunner{links: map[string]bool{"lan0": true}}
			s := New(runner, t.TempDir())
			if err := s.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			runner.outputs = map[string]string{"tc qdisc show dev lan0": tt.qdisc}
			if err := s.Health(context.Background(), cfg); err == nil {
				t.Fatal("qdisc mismatch accepted")
			}
		})
	}
}

func TestClientApplyErrorPathsPreserveOwnership(t *testing.T) {
	runner := &fakeRunner{links: map[string]bool{"lan0": true}}
	dir := t.TempDir()
	s := New(runner, dir)
	cfg := clientLimitConfig()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	// An update to an already-owned interface must not run the new-object cleanup path.
	cfg.Clients[0].DownKbit = 6000
	runner.errors = map[string]error{
		"tc class replace dev lan0 parent 1: classid 1:1 htb rate 10gbit ceil 10gbit": errors.New("update failed"),
	}
	if err := s.Apply(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "update failed") {
		t.Fatalf("existing client update error=%v", err)
	}
	owned, _ := s.readClientInterfaces()
	if len(owned) != 1 || owned[0] != "lan0" {
		t.Fatalf("existing ownership lost: %+v", owned)
	}

	// A failed stale cleanup must likewise retain ownership for retry.
	runner.errors = map[string]error{"tc qdisc del dev lan0 root": errors.New("cleanup denied")}
	cfg.Clients = nil
	if err := s.Apply(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "cleanup denied") {
		t.Fatalf("stale cleanup error=%v", err)
	}
	owned, _ = s.readClientInterfaces()
	if len(owned) != 1 {
		t.Fatalf("stale ownership lost: %+v", owned)
	}
}

func TestApplyClientsRejectsStateAndDesiredErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "owned-qos-clients.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(&fakeRunner{links: map[string]bool{}}, dir)
	if err := s.applyClients(context.Background(), config.Default()); err == nil {
		t.Fatal("malformed ownership ignored by applyClients")
	}

	if err := os.Remove(filepath.Join(dir, "owned-qos-clients.json")); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Clients = []config.Client{{MAC: "aa:bb:cc:dd:ee:ff", Network: "missing", DownKbit: 1000}}
	if err := s.applyClients(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "не найден") {
		t.Fatalf("invalid desired clients accepted: %v", err)
	}

	if err := s.writeClientInterfaces(nil); err != nil {
		t.Fatal(err)
	}
	if names, err := s.readClientInterfaces(); err != nil || len(names) != 0 {
		t.Fatalf("nil client ownership was not persisted as []: %+v err=%v", names, err)
	}
}
