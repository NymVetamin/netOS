package manage

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUninstallLaunchesIndependentWorkerAfterConsent(t *testing.T) {
	for _, tc := range []struct{ input, flag string }{{"y\ny\n", "--backup"}, {"y\nn\n", "--no-backup"}} {
		m, out := testManager()
		m.LaunchUninstall = m.launchUninstall
		m.In = strings.NewReader(tc.input)
		m.Getenv = func(string) string { return "192.0.2.5 40000 192.0.2.1 22" }
		m.AcquireMaintenance = func() (func(), error) { t.Fatal("SSH client holds worker lock"); return nil, nil }
		var commands []command
		m.Run = func(_ context.Context, c command) error { commands = append(commands, c); return nil }
		if err := m.Execute(context.Background(), []string{"uninstall"}); err != nil {
			t.Fatal(err)
		}
		if len(commands) != 1 || commands[0].name != "systemd-run" {
			t.Fatalf("commands: %+v", commands)
		}
		args := commands[0].args
		for _, want := range []string{"--wait", "--collect", "--service-type=exec", "--property=StandardInput=null", "--property=StandardOutput=journal", "--setenv=SSH_CONNECTION=192.0.2.5 40000 192.0.2.1 22", m.CLI, "internal-uninstall", tc.flag} {
			if !contains(args, want) {
				t.Fatalf("missing %q: %v", want, args)
			}
		}
		for _, forbidden := range []string{"--pipe", "--pty", "--scope"} {
			if contains(args, forbidden) {
				t.Fatal(args)
			}
		}
		if !strings.Contains(out.String(), "netOS удалён") {
			t.Fatal(out.String())
		}
	}
}

func TestUninstallWorkerFailureAndCancelledConsent(t *testing.T) {
	for _, input := range []string{"n\n", "y\nn\n"} {
		m, out := testManager()
		m.LaunchUninstall = m.launchUninstall
		m.In = strings.NewReader(input)
		calls := 0
		m.Run = func(context.Context, command) error { calls++; return errors.New("worker failed") }
		err := m.Execute(context.Background(), []string{"uninstall"})
		if (err != nil) != (calls == 1) || (input == "n\n" && calls != 0) || strings.Contains(out.String(), "netOS удалён") {
			t.Fatalf("calls=%d err=%v output=%s", calls, err, out)
		}
	}
}

// The worker runs detached and writes only to its log; the terminal must still
// get the reason. A result left by an earlier run is never shown as this one's.
func TestUninstallFailureShowsWorkerReason(t *testing.T) {
	for _, tc := range []struct {
		name, previous, appended, want string
	}{
		{"reason", "", "2026-11-17T10:47:26Z Завершение удаления: причина\nЧто сделать: совет\n", "удаление не выполнено: причина\nЧто сделать: совет\nПодробности: "},
		{"after earlier runs", "x Завершение удаления: старая причина\nx Завершение удаления: <nil>\n", "x Завершение удаления: новая причина\n", "удаление не выполнено: новая причина\n"},
		{"large transcript", "x Завершение удаления: старая причина\n", strings.Repeat("x", 8<<20) + "\nx Завершение удаления: большая ошибка\nподробности\n", "удаление не выполнено: большая ошибка\nподробности\n"},
		{"crashed worker", "x Завершение удаления: старая причина\n", "x > systemctl stop netosd\n", "запуск или выполнение удаления завершилось ошибкой"},
		{"no log", "", "", "запуск или выполнение удаления завершилось ошибкой"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, out := testManager()
			sandbox(t, m)
			m.LaunchUninstall = m.launchUninstall
			path := m.sys(uninstallLogPath)
			_ = os.MkdirAll(filepath.Dir(path), 0755)
			if tc.previous != "" {
				_ = os.WriteFile(path, []byte(tc.previous), 0600)
			}
			m.Run = func(context.Context, command) error {
				if tc.appended != "" {
					f, _ := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
					f.WriteString(tc.appended)
					f.Close()
				}
				return errors.New("exit status 1: Running as unit: netos-uninstall.service")
			}
			err := m.uninstall(context.Background(), true, false, false, true)
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "старая причина") ||
				(strings.HasPrefix(tc.want, "удаление не выполнено") && strings.Contains(err.Error(), "Running as unit")) {
				t.Fatalf("err=%v", err)
			}
			if strings.Contains(out.String(), "netOS удалён") {
				t.Fatal(out.String())
			}
		})
	}
}

func TestUninstallResultLogBoundaries(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	path := m.sys(uninstallLogPath)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	const marker = " Завершение удаления: "
	for _, reason := range []string{"<nil>", strings.Repeat("x", 32760), strings.Repeat("y", 65540), strings.Repeat("z", (4<<20)+1)} {
		data := "prefix" + marker + "earlier\nworker" + marker + reason + "\n"
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		want := reason[:min(len(reason), 4<<20)]
		if want == "<nil>" {
			want = ""
		}
		for _, start := range []int64{0, int64(len(data) + 1)} {
			if got := m.uninstallResult(start); got != want {
				t.Fatalf("start %d: got %d bytes, want %d", start, len(got), len(want))
			}
		}
		if got := m.uninstallResult(int64(strings.LastIndex(data, marker) + 1)); got != "" {
			t.Fatal("included a marker from before this run")
		}
	}
}

func BenchmarkUninstallResult(b *testing.B) {
	for _, size := range []int{1024, 8 << 20} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			m := &Manager{Root: b.TempDir()}
			path := m.sys(uninstallLogPath)
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				b.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(strings.Repeat("x", size)+"\nworker Завершение удаления: причина\n"), 0600); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.uninstallResult(0)
			}
		})
	}
}

func TestInternalUninstallLocksAndDoesNotRelaunch(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	m.LaunchUninstall = func(context.Context, bool, bool) error { t.Fatal("recursive launch"); return nil }
	locked, released := false, false
	m.AcquireMaintenance = func() (func(), error) { locked = true; return func() { released = true }, nil }
	m.Run = func(context.Context, command) error {
		if !locked {
			t.Fatal("no lock")
		}
		return nil
	}
	if err := m.Execute(context.Background(), []string{"internal-uninstall", "--no-backup"}); err != nil {
		t.Fatal(err)
	}
	if !locked || !released {
		t.Fatal("worker did not own lock")
	}
	log, err := os.ReadFile(m.sys(uninstallLogPath))
	if err != nil || !strings.Contains(string(log), "Завершение удаления: <nil>") {
		t.Fatalf("log=%s err=%v", log, err)
	}
}

func TestDefaultRouteWaitRejectsIPv4LL(t *testing.T) {
	for _, tc := range []struct {
		route string
		valid bool
	}{
		{"default dev eth0 scope link src 169.254.147.167 metric 1001009", false},
		{"default via 169.254.1.1 dev eth0", false},
		{"default via 192.0.2.1 dev eth0 linkdown", false},
		{"blackhole default", false},
		{"default via 192.0.2.1 dev eth0 proto dhcp", true},
		{"default dev ppp0 scope link", true},
	} {
		if got := usableDefaultRoute(tc.route); got != tc.valid {
			t.Errorf("%s: %v", tc.route, got)
		}
	}
	m, _ := testManager()
	reads := 0
	m.Output = func(context.Context, string, ...string) (string, error) {
		reads++
		if reads == 1 {
			return "default dev eth0 src 169.254.1.2", nil
		}
		return "default via 192.0.2.1 dev eth0", nil
	}
	if !m.waitDefaultRoute(context.Background(), 1) || reads != 2 {
		t.Fatalf("reads=%d", reads)
	}
}

func TestUninstallRetryMissingFirewallToolsRequiresProof(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	b := &systemBaseline{}
	for _, tc := range []struct {
		output string
		valid  bool
	}{
		{`{"nftables":[]}`, true},
		{`{"nftables":[{"chain":{"policy":"accept"}}]}`, true},
		{`{"nftables":[{"chain":{"policy":"drop"}}]}`, false},
		{`{"nftables":[{"rule":{}}]}`, false},
		{`{}`, false}, {`broken`, false},
	} {
		m.Output = func(context.Context, string, ...string) (string, error) { return tc.output, nil }
		if got := m.uninstallFirewallAlreadyRestored(context.Background(), b, exec.ErrNotFound); got != tc.valid {
			t.Fatalf("%s: %v", tc.output, got)
		}
	}
	m.Output = func(context.Context, string, ...string) (string, error) { return `{"nftables":[]}`, nil }
	if m.uninstallFirewallAlreadyRestored(context.Background(), &systemBaseline{IPTables4: "saved rules"}, exec.ErrNotFound) || m.uninstallFirewallAlreadyRestored(context.Background(), b, errors.New("permission denied")) {
		t.Fatal("unsafe bypass")
	}
	p := m.sys("/proc/net/ip_tables_names")
	_ = os.MkdirAll(filepath.Dir(p), 0755)
	_ = os.WriteFile(p, []byte("filter\n"), 0600)
	if m.uninstallFirewallAlreadyRestored(context.Background(), b, exec.ErrNotFound) {
		t.Fatal("unverified legacy firewall")
	}
}

func TestUninstallRetryAfterPackagePurge(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		m, _ := testManager()
		sandbox(t, m)
		baseline, _ := json.Marshal(systemBaseline{Version: 1, Sysctl: map[string]string{}})
		for path, data := range map[string][]byte{
			m.sys(systemBaselineDir + "/state.json"): baseline,
			m.Binary:                                 []byte("binary"), m.CLI: []byte("cli"), m.Unit: []byte("unit"),
			filepath.Join(m.StateDir, "netos.db"): []byte("saved database"),
		} {
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		m.Run = func(_ context.Context, c command) error {
			if c.name == "iptables-restore" {
				return exec.ErrNotFound
			}
			return nil
		}
		m.Output = func(_ context.Context, name string, args ...string) (string, error) {
			if name == "ebtables-save" {
				return "", exec.ErrNotFound
			}
			if name == "nft" {
				if len(args) > 0 && args[0] == "list" {
					return "", exec.ErrNotFound
				}
				if blocked {
					return `{"nftables":[{"chain":{"policy":"drop"}}]}`, nil
				}
				return `{"nftables":[]}`, nil
			}
			return "", nil
		}
		err := m.Execute(context.Background(), []string{"internal-uninstall", "--no-backup"})
		if (err != nil) != blocked {
			t.Fatalf("blocked=%v err=%v", blocked, err)
		}
		for _, path := range []string{m.Binary, m.CLI, m.Unit, m.StateDir, m.sys(systemBaselineDir)} {
			_, err := os.Stat(path)
			if blocked && err != nil {
				t.Fatalf("recovery data lost: %s", path)
			}
			if !blocked && !os.IsNotExist(err) {
				t.Fatalf("residue: %s (%v)", path, err)
			}
		}
	}
}

func TestUninstallFirewallCheckpointBoundToBaselineAndInvalidated(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	b := &systemBaseline{Version: 1, IPTables4: "*filter\n:INPUT DROP [0:0]\nCOMMIT\n"}
	m.Output = func(context.Context, string, ...string) (string, error) { return "", exec.ErrNotFound }
	if m.uninstallFirewallAlreadyRestored(context.Background(), b, exec.ErrNotFound) {
		t.Fatal("missing tools accepted without completed restore")
	}
	if err := m.recordUninstallFirewallRestored(b); err != nil {
		t.Fatal(err)
	}
	if !m.uninstallFirewallAlreadyRestored(context.Background(), b, exec.ErrNotFound) {
		t.Fatal("completed restore requires purged tools")
	}
	changed := *b
	changed.Hostname = "different-baseline"
	if m.uninstallFirewallAlreadyRestored(context.Background(), &changed, exec.ErrNotFound) {
		t.Fatal("accepted checkpoint for a different baseline")
	}
	if m.uninstallFirewallAlreadyRestored(context.Background(), b, errors.New("permission denied")) {
		t.Fatal("checkpoint hid an unrelated error")
	}
	if err := InvalidateUninstallCheckpoint(m.Root); err != nil {
		t.Fatal(err)
	}
	if m.uninstallFirewallAlreadyRestored(context.Background(), b, exec.ErrNotFound) {
		t.Fatal("new Apply still trusts previous uninstall")
	}
}

func TestLegacyPermissiveFirewallDump(t *testing.T) {
	for _, tc := range []struct {
		dump string
		want bool
	}{
		{"", true}, {"# saved\n*filter\n:INPUT ACCEPT [42:99]\nCOMMIT\n", true},
		{"*filter\n:INPUT DROP [0:0]\nCOMMIT", false},
		{"*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -j ACCEPT\nCOMMIT", false},
		{"*filter\n:INPUT ACCEPT [0:0]", false}, {"garbage", false},
	} {
		if got := permissiveFirewallDump(tc.dump); got != tc.want {
			t.Fatalf("dump %q got %v want %v", tc.dump, got, tc.want)
		}
	}
}

func TestOldFirewallCheckpointRequiresCompleteRestore(t *testing.T) {
	for _, tc := range []struct {
		name, v4, v6 string
		hasV6, valid bool
	}{
		{"empty with IPv6", "", "", true, false},
		{"empty IPv4 only", "", "", false, true},
		{"complete", emptyFirewall4, emptyFilter + emptyMangle, true, true},
		{"only v4 captured", emptyFirewall4, "", false, true},
		{"partial v4", emptyFilter, emptyFilter + emptyMangle, true, false},
		{"partial v6", emptyFirewall4, emptyFilter, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := testManager()
			sandbox(t, m)
			b := &systemBaseline{Version: 1, IPTables4: tc.v4, IPTables6: tc.v6, IPTables6Exists: tc.hasV6}
			data, err := json.Marshal(b)
			if err != nil {
				t.Fatal(err)
			}
			path := m.sys(uninstallFirewallCheckpoint)
			if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, []byte(fmt.Sprintf("%x\n", sha256.Sum256(data))), 0600); err != nil {
				t.Fatal(err)
			}
			m.Output = func(context.Context, string, ...string) (string, error) { return "", exec.ErrNotFound }
			m.Run = func(context.Context, command) error { return exec.ErrNotFound }
			err = m.restoreBaselineFirewall(context.Background(), b)
			if tc.valid && err != nil || !tc.valid && (!errors.Is(err, exec.ErrNotFound) || !strings.Contains(err.Error(), "утилит")) {
				t.Fatalf("old checkpoint: %v", err)
			}
			if err = m.recordUninstallFirewallRestored(b); err != nil {
				t.Fatal(err)
			}
			if err = m.restoreBaselineFirewall(context.Background(), b); err != nil {
				t.Fatalf("current checkpoint: %v", err)
			}
		})
	}
}
