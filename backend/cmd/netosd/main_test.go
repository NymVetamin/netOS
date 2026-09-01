package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/api"
	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/bootstrap"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/store"
	"github.com/netos-router/netos/internal/subsys/channels"
	"github.com/netos-router/netos/internal/subsys/ddns"
	"github.com/netos-router/netos/internal/subsys/multiwan"
	"github.com/netos-router/netos/internal/system"
)

type testLogger struct{ messages []string }

func (l *testLogger) Infof(format string, args ...any)  { l.messages = append(l.messages, format) }
func (l *testLogger) Warnf(format string, args ...any)  { l.messages = append(l.messages, format) }
func (l *testLogger) Errorf(format string, args ...any) { l.messages = append(l.messages, format) }

type testRunner struct{}

func (testRunner) Run(_ context.Context, name string, _ ...string) (string, error) {
	if name == os.Getenv("NETOS_MAIN_FAIL_COMMAND") {
		return "", errors.New("injected command failure")
	}
	return "", nil
}
func (testRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return testRunner{}.Run(ctx, name, args...)
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestReadyMessageDoesNotExposeInitialPassword(t *testing.T) {
	var output strings.Builder
	printReady(&output, []string{"192.0.2.1"}, 8443)

	if strings.Contains(output.String(), "Пароль:") {
		t.Fatal("вывод демона по-прежнему обещает или печатает пароль")
	}
	if !strings.Contains(output.String(), credentialsPath) {
		t.Fatal("администратору не указано безопасное местонахождение учётных данных")
	}
}

func TestPanelAddressesUsesEnabledUniqueNetworksWANsAndFallback(t *testing.T) {
	cfg := config.Default()
	cfg.System.Hostname = "router.test"
	cfg.Networks = []config.Network{
		{Enabled: true, RouterAddress: "192.168.10.1/24"},
		{Enabled: false, RouterAddress: "192.168.20.1/24"},
	}
	cfg.WANs = []config.WAN{
		{Enabled: true, Address: "203.0.113.2/24"},
		{Enabled: true, Address: "192.168.10.1/24"},
		{Enabled: false, Address: "198.51.100.2/24"},
	}
	got := panelAddresses(cfg)
	if strings.Join(got, ",") != "192.168.10.1,203.0.113.2" {
		t.Fatalf("panel addresses=%v", got)
	}
	cfg.Networks, cfg.WANs = nil, nil
	if got := panelAddresses(cfg); len(got) != 1 || got[0] != "router.test" {
		t.Fatalf("fallback addresses=%v", got)
	}
}

func TestEnsureAdminCreatesPrivateCredentialsOnce(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "netos.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	oldPath := credentialsPath
	credentialsPath = filepath.Join(t.TempDir(), "initial-credentials")
	t.Cleanup(func() { credentialsPath = oldPath })
	logger := &testLogger{}
	cfg := config.Default()
	output := captureStdout(t, func() {
		if err := ensureAdmin(st, cfg, logger); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(output, "Пароль:") {
		t.Fatal("initial password leaked to stdout")
	}
	data, err := os.ReadFile(credentialsPath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(credentialsPath)
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("credentials mode=%v err=%v", info.Mode().Perm(), err)
	}
	var password string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Пароль:") {
			password = strings.TrimSpace(strings.TrimPrefix(line, "Пароль:"))
		}
	}
	user, err := st.UserByName("admin")
	if err != nil || len(password) != 16 || !api.VerifyPassword(password, user.PasswordHash) {
		t.Fatalf("credentials do not authenticate: password length=%d err=%v", len(password), err)
	}
	before := string(data)
	if err := ensureAdmin(st, cfg, logger); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(credentialsPath)
	if err != nil || string(after) != before {
		t.Fatalf("second ensureAdmin changed credentials: err=%v", err)
	}
}

func TestLoadOrBootstrapPrefersActiveThenLatestRevision(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "netos.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	logger := &testLogger{}
	one := config.Default()
	one.System.Hostname = "active"
	oneID, err := st.CreateRevision(one, "test", "one")
	if err != nil || st.MarkActive(oneID) != nil {
		t.Fatal(err)
	}
	two := config.Default()
	two.System.Hostname = "latest"
	twoID, err := st.CreateRevision(two, "test", "two")
	if err != nil {
		t.Fatal(err)
	}
	cfg, id, err := loadOrBootstrap(context.Background(), st, testRunner{}, logger)
	if err != nil || id != oneID || cfg.System.Hostname != "active" {
		t.Fatalf("active result id=%d cfg=%v err=%v", id, cfg, err)
	}
	if err := st.SetRevisionState(oneID, store.StateSuperseded); err != nil {
		t.Fatal(err)
	}
	cfg, id, err = loadOrBootstrap(context.Background(), st, testRunner{}, logger)
	if err != nil || id != twoID || cfg.System.Hostname != "latest" {
		t.Fatalf("latest result id=%d cfg=%v err=%v", id, cfg, err)
	}
}

func TestLoadOrBootstrapCreatesFirstRevisionAndPropagatesDetectionError(t *testing.T) {
	oldDetect := detectInitial
	t.Cleanup(func() { detectInitial = oldDetect })
	logger := &testLogger{}

	t.Run("first boot", func(t *testing.T) {
		st, err := store.Open(filepath.Join(t.TempDir(), "netos.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		detectInitial = func(context.Context, system.Runner) (*bootstrap.Detected, error) {
			return &bootstrap.Detected{
				WANInterface: "eth0", WANAddress: "192.0.2.2/24", WANGateway: "192.0.2.1",
				AllInterfaces: []string{"eth0", "eth1"}, LANCandidates: []string{"eth1"},
			}, nil
		}
		cfg, id, err := loadOrBootstrap(context.Background(), st, testRunner{}, logger)
		if err != nil || id == 0 || len(cfg.WANs) != 1 || cfg.WANs[0].Interface != "if-wan" || len(cfg.Interfaces) == 0 || cfg.Interfaces[0].Name != "eth0" {
			t.Fatalf("id=%d cfg=%+v err=%v", id, cfg, err)
		}
		latest, err := st.LatestRevision()
		if err != nil || latest.ID != id {
			t.Fatalf("latest=%+v err=%v", latest, err)
		}
	})

	t.Run("detection failure", func(t *testing.T) {
		st, err := store.Open(filepath.Join(t.TempDir(), "netos.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		detectInitial = func(context.Context, system.Runner) (*bootstrap.Detected, error) {
			return nil, errors.New("detect failed")
		}
		if _, _, err := loadOrBootstrap(context.Background(), st, testRunner{}, logger); err == nil || !strings.Contains(err.Error(), "detect failed") {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("initial panel port override", func(t *testing.T) {
		t.Setenv("NETOS_INITIAL_PORT", "9443")
		st, err := store.Open(filepath.Join(t.TempDir(), "netos.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		detectInitial = func(context.Context, system.Runner) (*bootstrap.Detected, error) {
			return &bootstrap.Detected{WANInterface: "eth0", AllInterfaces: []string{"eth0"}}, nil
		}
		cfg, _, err := loadOrBootstrap(context.Background(), st, testRunner{}, logger)
		if err != nil || cfg.System.Panel.Port != 9443 {
			t.Fatalf("port=%d err=%v", cfg.System.Panel.Port, err)
		}
	})

	for _, value := range []string{"zero", "0", "65536", "53"} {
		t.Run("invalid initial port "+value, func(t *testing.T) {
			t.Setenv("NETOS_INITIAL_PORT", value)
			st, err := store.Open(filepath.Join(t.TempDir(), "netos.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			detectInitial = func(context.Context, system.Runner) (*bootstrap.Detected, error) {
				return &bootstrap.Detected{WANInterface: "eth0", AllInterfaces: []string{"eth0"}}, nil
			}
			if _, _, err := loadOrBootstrap(context.Background(), st, testRunner{}, logger); err == nil || !strings.Contains(err.Error(), "NETOS_INITIAL_PORT") {
				t.Fatalf("invalid value %q returned %v", value, err)
			}
		})
	}
}

func TestLoadOrBootstrapDoesNotHideCorruptLatestRevision(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "netos.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO revisions (created_at, author, comment, config, state) VALUES (1, 'test', 'corrupt', '{', 'draft')`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	oldDetect := detectInitial
	detectInitial = func(context.Context, system.Runner) (*bootstrap.Detected, error) {
		t.Fatal("corrupt storage must not trigger bootstrap detection")
		return nil, nil
	}
	t.Cleanup(func() { detectInitial = oldDetect })
	if _, _, err := loadOrBootstrap(context.Background(), st, testRunner{}, &testLogger{}); err == nil || !strings.Contains(err.Error(), "последней ревизии") {
		t.Fatalf("error=%v", err)
	}
}

func TestCLIOutputAndSubsystemRegistration(t *testing.T) {
	cfg := config.Default()
	for _, artifact := range renderableArtifacts {
		if !strings.Contains(renderFlagHelp(), artifact) {
			t.Fatalf("render flag help lacks %q: %s", artifact, renderFlagHelp())
		}
	}
	if err := renderArtifact("not-real", cfg); err == nil {
		t.Fatal("unknown render artifact accepted")
	}
	rendered := captureStdout(t, func() {
		if err := renderArtifact("sysctl", cfg); err != nil {
			t.Fatal(err)
		}
	})
	if rendered == "" {
		t.Fatal("sysctl render is empty")
	}
	clean := captureStdout(t, func() { printPlan(nil) })
	if !strings.Contains(clean, "применять нечего") {
		t.Fatalf("clean plan output=%q", clean)
	}
	dirty := captureStdout(t, func() {
		printPlan([]apply.Action{{Subsystem: "firewall", Kind: "update", Target: "rules", Detail: "changed", Disruptive: true}})
	})
	if !strings.Contains(dirty, "firewall") || !strings.Contains(dirty, "changed") {
		t.Fatalf("dirty plan output=%q", dirty)
	}
	summary := captureStdout(t, func() { printSummary(cfg) })
	if !strings.Contains(summary, cfg.System.Hostname) {
		t.Fatalf("summary output=%q", summary)
	}

	runner := testRunner{}
	logger := &testLogger{}
	engine := apply.NewEngine(nil, true)
	mw := multiwan.New(runner, t.TempDir(), logger)
	ch := channels.New(runner, t.TempDir(), logger)
	dynamicDNS := ddns.New(logger)
	if err := registerSubsystems(engine, runner, logger, mw, ch, dynamicDNS); err != nil {
		t.Fatal(err)
	}
	if err := registerSubsystems(engine, runner, logger, mw, ch, dynamicDNS); err != nil {
		t.Fatalf("idempotent registration failed: %v", err)
	}
}

func TestMainCLIProcess(t *testing.T) {
	if os.Getenv("NETOS_MAIN_HELPER") != "1" {
		return
	}
	separator := -1
	for i, arg := range os.Args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 {
		t.Fatal("helper arguments separator is missing")
	}
	root := os.Getenv("NETOS_MAIN_ROOT")
	credentialsPath = filepath.Join(root, "initial-credentials")
	stateDir = filepath.Join(root, "generated")
	tlsDir = filepath.Join(root, "tls")
	leasePath = filepath.Join(root, "dnsmasq.leases")
	readyPath = filepath.Join(root, "netosd.ready")
	newRunner = func() system.Runner { return testRunner{} }
	detectInitial = func(context.Context, system.Runner) (*bootstrap.Detected, error) {
		return &bootstrap.Detected{
			WANInterface: "eth0", WANAddress: "192.0.2.2/24", WANGateway: "192.0.2.1",
			AllInterfaces: []string{"eth0", "eth1"}, LANCandidates: []string{"eth1"},
		}, nil
	}
	flag.CommandLine = flag.NewFlagSet("netosd", flag.ExitOnError)
	os.Args = append([]string{os.Getenv("NETOS_MAIN_ARGV0")}, os.Args[separator+1:]...)
	main()
}

func seededCLIStore(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "netos.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	id, err := st.CreateRevision(cfg, "test", "seed main CLI")
	if err == nil {
		err = st.MarkActive(id)
	}
	closeErr := st.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	return dbPath
}

func runMainCLI(t *testing.T, argv0 string, args ...string) (string, error) {
	t.Helper()
	root := t.TempDir()
	childArgs := append([]string{"-test.run=^TestMainCLIProcess$", "--"}, args...)
	cmd := exec.Command(os.Args[0], childArgs...)
	cmd.Env = append(os.Environ(),
		"NETOS_MAIN_HELPER=1",
		"NETOS_MAIN_ROOT="+root,
		"NETOS_MAIN_ARGV0="+argv0,
	)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func TestMainCLIEndToEnd(t *testing.T) {
	t.Run("daemon version flag", func(t *testing.T) {
		output, err := runMainCLI(t, "netosd", "-version")
		if err != nil || !strings.Contains(output, "netOS dev") {
			t.Fatalf("output=%q err=%v", output, err)
		}
	})

	t.Run("management alias version", func(t *testing.T) {
		output, err := runMainCLI(t, "netos", "version")
		if err != nil || !strings.Contains(output, "dev") {
			t.Fatalf("output=%q err=%v", output, err)
		}
	})

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "init existing config", args: []string{"-init"}, want: "1"},
		{name: "render sysctl", args: []string{"-render", "sysctl"}, want: "net.ipv4"},
		{name: "dry run apply", args: []string{"-dry-run", "-apply"}, want: "Конфигурация"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := seededCLIStore(t)
			args := append([]string{"-db", dbPath}, tc.args...)
			output, err := runMainCLI(t, "netosd", args...)
			if err != nil || !strings.Contains(output, tc.want) {
				t.Fatalf("output=%q err=%v", output, err)
			}
		})
	}

	t.Run("plan reports missing live-system prerequisite", func(t *testing.T) {
		t.Setenv("NETOS_MAIN_FAIL_COMMAND", "iptables-save")
		dbPath := seededCLIStore(t)
		output, err := runMainCLI(t, "netosd", "-db", dbPath, "-plan")
		if err == nil || !strings.Contains(output, "injected command failure") {
			t.Fatalf("output=%q err=%v", output, err)
		}
	})

	t.Run("unknown render fails", func(t *testing.T) {
		dbPath := seededCLIStore(t)
		output, err := runMainCLI(t, "netosd", "-db", dbPath, "-render", "not-real")
		if err == nil || output == "" {
			t.Fatalf("output=%q err=%v", output, err)
		}
	})

	t.Run("database open failure", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "netos.db")
		if err := os.Mkdir(dbPath, 0o700); err != nil {
			t.Fatal(err)
		}
		output, err := runMainCLI(t, "netosd", "-db", dbPath, "-init")
		if err == nil || output == "" {
			t.Fatalf("output=%q err=%v", output, err)
		}
	})
}

func runMainInProcess(t *testing.T, argv0 string, args ...string) string {
	t.Helper()
	oldArgs, oldFlags := os.Args, flag.CommandLine
	oldCredentials, oldState := credentialsPath, stateDir
	oldTLS, oldLease, oldReady := tlsDir, leasePath, readyPath
	oldRunner := newRunner
	root := t.TempDir()
	credentialsPath = filepath.Join(root, "initial-credentials")
	stateDir = filepath.Join(root, "generated")
	tlsDir = filepath.Join(root, "tls")
	leasePath = filepath.Join(root, "dnsmasq.leases")
	readyPath = filepath.Join(root, "netosd.ready")
	newRunner = func() system.Runner { return testRunner{} }
	flag.CommandLine = flag.NewFlagSet("netosd", flag.ContinueOnError)
	os.Args = append([]string{argv0}, args...)
	t.Cleanup(func() {
		os.Args, flag.CommandLine = oldArgs, oldFlags
		credentialsPath, stateDir = oldCredentials, oldState
		tlsDir, leasePath, readyPath = oldTLS, oldLease, oldReady
		newRunner = oldRunner
	})
	return captureStdout(t, main)
}

func TestMainSuccessfulBranchesInProcess(t *testing.T) {
	t.Run("version", func(t *testing.T) {
		if output := runMainInProcess(t, "netosd", "-version"); !strings.Contains(output, "netOS dev") {
			t.Fatalf("output=%q", output)
		}
	})
	t.Run("management alias", func(t *testing.T) {
		if output := runMainInProcess(t, "netos", "version"); !strings.Contains(output, "dev") {
			t.Fatalf("output=%q", output)
		}
	})
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "init", args: []string{"-init"}, want: "1"},
		{name: "render", args: []string{"-render", "sysctl"}, want: "net.ipv4"},
		{name: "apply dry run verbose", args: []string{"-dry-run", "-v", "-apply"}, want: "Конфигурация"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := seededCLIStore(t)
			args := append([]string{"-db", dbPath}, tc.args...)
			if output := runMainInProcess(t, "netosd", args...); !strings.Contains(output, tc.want) {
				t.Fatalf("output=%q", output)
			}
		})
	}
}
