package socks

import (
	"context"
	"fmt"
	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

type fake struct {
	active bool
	fail   string
	calls  []string
}

func (f *fake) Run(_ context.Context, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	if f.fail != "" && strings.Contains(cmd, f.fail) {
		return "", fmt.Errorf("injected failure")
	}
	if strings.Contains(cmd, "systemctl stop") {
		f.active = false
	}
	if strings.Contains(cmd, "systemctl restart") {
		f.active = true
	}
	if strings.Contains(cmd, "is-active") {
		if f.active {
			return "active", nil
		}
		return "inactive", nil
	}
	return "", nil
}
func (f *fake) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return f.Run(ctx, name, args...)
}
func fixture() *config.Config {
	c := config.Default()
	c.Socks = config.Socks{Enabled: true, Port: 1080, Auth: true, Username: "test", Password: "test-password", Channel: "direct"}
	return c
}
func TestSocksRenderAndLifecycle(t *testing.T) {
	c := fixture()
	f := &fake{}
	root := t.TempDir()
	s := &Subsystem{Runner: f, StateDir: filepath.Join(root, "generated"), UnitDir: filepath.Join(root, "units")}
	ctx := context.Background()
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(s.StateDir, "socks.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"protocol": "socks"`, `"auth": "password"`, `"udp": false`, `"ForceIPv4"`, `"::/0"`} {
		if !strings.Contains(string(data), want) {
			t.Fatal(want)
		}
	}
	if strings.Contains(strings.Join(f.calls, " "), "systemctl enable") {
		t.Fatal("proxy starts before firewall at boot")
	}
	c.Socks.Port = 1081
	if err := (&Preparation{S: s}).Apply(ctx, c); err != nil || f.active {
		t.Fatal("listener not stopped before firewall change")
	}
	f.fail = "-test"
	if err := s.Apply(ctx, c); err == nil {
		t.Fatal("invalid config accepted")
	}
	f.fail = ""
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.Socks.Enabled = false
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	if f.active {
		t.Fatal("listener left active")
	}
	if _, err := os.Stat(filepath.Join(s.UnitDir, Unit)); !os.IsNotExist(err) {
		t.Fatal("unit left behind")
	}
}
func TestPreparedDisable(t *testing.T) {
	ctx := context.Background()
	cfg := fixture()
	r := &fake{}
	s := New(r, t.TempDir())
	s.UnitDir = t.TempDir()
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Socks.Enabled = false
	prepare, finish := Preparation{s}, AfterPreparation{s}
	if err := prepare.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	// A firewall failure between the two stages rolls back with a fresh pass.
	cfg.Socks.Enabled = true
	if err := prepare.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := finish.Apply(ctx, cfg); err != nil || !r.active {
		t.Fatalf("rollback: active=%v err=%v", r.active, err)
	}
	cfg.Socks.Enabled = false
	r.fail = "systemctl stop"
	if err := prepare.Apply(ctx, cfg); err == nil || !r.active {
		t.Fatalf("failed stop: active=%v err=%v", r.active, err)
	}
	r.calls, r.fail = nil, ""
	if err := prepare.Apply(ctx, cfg); err != nil || r.active {
		t.Fatalf("retry stop: active=%v err=%v", r.active, err)
	}
	conf, unit := s.paths()
	if _, err := os.Stat(unit); err != nil {
		t.Fatal("preparation must leave cleanup to the late stage", err)
	}
	for i := 0; i < 2; i++ {
		if err := finish.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
	}
	if want := []string{"systemctl stop " + Unit, "systemctl daemon-reload"}; !slices.Equal(r.calls, want) {
		t.Fatalf("disable and repeat: %v", r.calls)
	}
	for _, path := range []string{conf, unit, filepath.Join(s.StateDir, "socks.applied")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("cleanup %s: %v", path, err)
		}
	}
}

func TestSocksNeverFallsBackForMissingChannel(t *testing.T) {
	c := fixture()
	c.Socks.Channel = "missing"
	if _, err := Render(c); err == nil {
		t.Fatal("missing channel silently became direct")
	}
	c.Channels = append(c.Channels, config.Channel{ID: "vpn", Enabled: true, Type: "xray", Index: 2})
	c.Socks.Channel = "vpn"
	data, err := Render(c)
	if err != nil || !strings.Contains(string(data), `"mark":`) {
		t.Fatal(string(data), err)
	}
}

func TestDisableAfterInterruptedCandidateWrite(t *testing.T) {
	ctx := context.Background()
	s := New(&fake{}, t.TempDir())
	s.UnitDir = t.TempDir()
	cfg := fixture()
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	conf, unit := s.paths()
	candidate := filepath.Join(s.StateDir, "socks.candidate.json")
	// A nonempty directory at the file path makes unlink fail on all platforms.
	if err := os.Mkdir(candidate, 0700); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(candidate, "blocker")
	if err := os.WriteFile(blocker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	cfg.Socks.Enabled = false
	if err := s.Apply(ctx, cfg); err == nil {
		t.Fatal("candidate cleanup failure was ignored")
	}
	if _, err := os.Stat(unit); err != nil {
		t.Fatal("unit must remain available for cleanup retry", err)
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(candidate); err != nil {
		t.Fatal(err)
	}
	// An interrupted validation leaves the candidate beside the live config.
	data, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidate, data, 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(candidate); !os.IsNotExist(err) {
			t.Fatalf("candidate after disable: %v", err)
		}
	}
}

func TestUnchangedSocksValidatesLiveConfigAndChecksServiceOnce(t *testing.T) {
	ctx := context.Background()
	r := &fake{}
	s := New(r, t.TempDir())
	s.UnitDir = t.TempDir()
	cfg := fixture()
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	conf, _ := s.paths()
	validate := "/usr/local/bin/xray run -test -config " + conf
	probe := "systemctl is-active " + Unit
	for _, active := range []bool{true, false, true} {
		r.calls, r.active = nil, active
		if err := (AfterPreparation{s}).Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		want := []string{validate, probe}
		if !active {
			want = append(want, "systemctl restart "+Unit, probe)
		}
		if !slices.Equal(r.calls, want) {
			t.Fatalf("active=%v: calls %v, want %v", active, r.calls, want)
		}
	}
	r.calls, r.fail = nil, "-test"
	if err := s.Apply(ctx, cfg); err == nil || !slices.Equal(r.calls, []string{validate}) {
		t.Fatalf("invalid executable: calls=%v err=%v", r.calls, err)
	}
	r.fail = ""
	candidate := filepath.Join(s.StateDir, "socks.candidate.json")
	if err := os.WriteFile(candidate, []byte("interrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(candidate); !os.IsNotExist(err) {
		t.Fatalf("candidate left after retry: %v", err)
	}
	if runtime.GOOS == "linux" {
		for path, mode := range map[string]os.FileMode{
			conf: 0600, filepath.Join(s.UnitDir, Unit): 0644, filepath.Join(s.StateDir, "socks.applied"): 0600,
		} {
			if err := os.Chmod(path, 0666); err != nil {
				t.Fatal(err)
			}
			r.calls = nil
			if err := s.Apply(ctx, cfg); err != nil || slices.Contains(r.calls, "systemctl restart "+Unit) {
				t.Fatalf("mode repair: calls=%v err=%v", r.calls, err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != mode {
				t.Fatalf("mode not repaired: %v", err)
			}
		}
	}
}

func TestSocksStartsAfterFirewall(t *testing.T) {
	positions := map[string]int{}
	for i, name := range apply.Order {
		positions[name] = i
	}
	if positions["socks-prepare"] >= positions["firewall"] || positions["socks"] <= positions["firewall"] {
		t.Fatal("unsafe SOCKS lifecycle ordering")
	}
}

func TestPlanRestoresSocksFiles(t *testing.T) {
	c := fixture()
	f := &fake{}
	s := New(f, t.TempDir())
	s.UnitDir = t.TempDir()
	ctx := context.Background()
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	conf, unit := s.paths()
	check := func(want int) {
		t.Helper()
		calls := len(f.calls)
		actions, err := s.Plan(c, c)
		if err != nil || len(actions) != want || (want == 1 && !actions[0].Disruptive) || calls != len(f.calls) {
			t.Fatalf("actions=%v err=%v, runner calls=%d", actions, err, len(f.calls)-calls)
		}
	}
	check(0)
	for _, path := range []string{conf, unit} {
		for _, missing := range []bool{true, false} {
			if missing {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte("drift"), 0600); err != nil {
				t.Fatal(err)
			}
			check(1)
			f.fail = "-test"
			if err := s.Apply(ctx, c); err == nil {
				t.Fatal("validation failure ignored")
			}
			check(1)
			f.fail = ""
			f.calls = nil
			if err := s.Apply(ctx, c); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(f.calls, "systemctl restart "+Unit) {
				t.Fatal("missing planned restart")
			}
			check(0)
		}
	}
	c.Socks.Enabled = false
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	check(0)
}

func BenchmarkSocksPlan(b *testing.B) {
	for _, n := range []int{32, 512} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			c := fixture()
			for i := 0; i < n; i++ {
				c.Channels = append(c.Channels, config.Channel{ID: fmt.Sprint(i), Enabled: true, Type: "direct"})
			}
			old := *c
			s := New(&fake{}, b.TempDir())
			s.UnitDir = b.TempDir()
			if err := s.Apply(context.Background(), c); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if actions, err := s.Plan(&old, c); err != nil || len(actions) != 0 {
					b.Fatal(actions, err)
				}
			}
		})
	}
}
