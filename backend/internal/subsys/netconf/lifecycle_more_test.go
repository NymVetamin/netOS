package netconf

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingCommandRunner struct {
	base *backendUnitRunner
	fail string
}

func (r *failingCommandRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	if command == r.fail {
		return "", fmt.Errorf("injected failure")
	}
	return r.base.Run(ctx, name, args...)
}

func (r *failingCommandRunner) RunInput(ctx context.Context, input, name string, args ...string) (string, error) {
	return r.base.RunInput(ctx, input, name, args...)
}

func useTemporaryPaths(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	oldIfupdown, oldNetworkd := ifupdownPath, networkdDir
	oldWait, oldOwnership, oldNM := waitOnlineDropIn, networkdOwnershipDropIn, nmConfPath
	ifupdownPath = filepath.Join(root, "network", "interfaces.d", "netos.conf")
	networkdDir = filepath.Join(root, "systemd", "network")
	waitOnlineDropIn = filepath.Join(root, "systemd", "wait-online.d", "99-netos.conf")
	networkdOwnershipDropIn = filepath.Join(root, "systemd", "networkd.conf.d", "99-netos.conf")
	nmConfPath = filepath.Join(root, "NetworkManager", "conf.d", "99-netos.conf")
	t.Cleanup(func() {
		ifupdownPath, networkdDir = oldIfupdown, oldNetworkd
		waitOnlineDropIn, networkdOwnershipDropIn, nmConfPath = oldWait, oldOwnership, oldNM
	})
}

func TestApplyNetworkdIsExactlyIdempotent(t *testing.T) {
	useTemporaryPaths(t)
	r := newBackendUnitRunner()
	r.active["systemd-networkd.service"] = true
	r.enabled["systemd-networkd.service"] = true
	r.masked["systemd-networkd.socket"] = false
	cfg := routerConfig()
	cfg.System.NetworkBackend = "networkd"
	s := New(r, nil)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	r.commands = nil
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	for _, command := range r.commands {
		for _, mutation := range []string{" reload", " restart", " enable", " start", " stop", " mask", " unmask", " disable"} {
			if strings.Contains(command, mutation) {
				t.Fatalf("clean Apply mutated runtime: %s (all commands: %v)", command, r.commands)
			}
		}
	}
}

func TestHealthAndPlanDetectManagedFileDrift(t *testing.T) {
	useTemporaryPaths(t)
	r := newBackendUnitRunner()
	r.active["systemd-networkd.service"] = true
	r.enabled["systemd-networkd.service"] = true
	cfg := routerConfig()
	cfg.System.NetworkBackend = "networkd"
	s := New(r, nil)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(networkdDir, "05-netos-eth0.network")
	if err := os.WriteFile(path, []byte("corrupt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("corrupted managed file passed Health")
	}
	actions, err := s.Plan(cfg, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) == 0 {
		t.Fatal("corrupted managed file was absent from Plan")
	}
	if err := os.WriteFile(filepath.Join(networkdDir, "05-netos-stale.network"), []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("unexpected managed file passed Health")
	}
}

func TestMissingSelectedBackendDoesNotMutateFiles(t *testing.T) {
	useTemporaryPaths(t)
	r := newBackendUnitRunner()
	delete(r.present, "systemd-networkd.service")
	cfg := routerConfig()
	cfg.System.NetworkBackend = "networkd"
	err := New(r, nil).Apply(context.Background(), cfg)
	if err == nil {
		t.Fatal("missing selected backend was accepted")
	}
	var found bool
	_ = filepath.Walk(filepath.Dir(networkdDir), func(_ string, info os.FileInfo, walkErr error) error {
		if walkErr == nil && info != nil && !info.IsDir() {
			found = true
		}
		return nil
	})
	if found {
		t.Fatal("preflight failure left generated files")
	}
}

func TestHealthDetectsWrongManagedFileMode(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("Windows does not preserve Unix permission bits")
	}
	useTemporaryPaths(t)
	r := newBackendUnitRunner()
	r.active["systemd-networkd.service"] = true
	r.enabled["systemd-networkd.service"] = true
	cfg := routerConfig()
	cfg.System.NetworkBackend = "networkd"
	s := New(r, nil)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(networkdDir, "05-netos-eth0.network")
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("wrong mode passed Health")
	}
}

func TestNetworkManagerReloadFailureRestoresPreviousFile(t *testing.T) {
	useTemporaryPaths(t)
	base := newBackendUnitRunner()
	base.present["NetworkManager.service"] = true
	base.active["NetworkManager.service"] = true
	r := &failingCommandRunner{base: base, fail: "systemctl reload NetworkManager.service"}
	old := []byte("[keyfile]\nunmanaged-devices=interface-name:old0\n")
	if err := os.MkdirAll(filepath.Dir(nmConfPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nmConfPath, old, 0o644); err != nil {
		t.Fatal(err)
	}
	err := New(r, nil).syncNetworkManager(context.Background(), []string{"eth0"})
	if err == nil {
		t.Fatal("reload failure was ignored")
	}
	got, readErr := os.ReadFile(nmConfPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != string(old) {
		t.Fatalf("reload failure left new file: %q", got)
	}
}

func TestHealthRequiresExactNetworkdMaskOwnership(t *testing.T) {
	useTemporaryPaths(t)
	r := newBackendUnitRunner()
	r.active["networking.service"] = true
	r.enabled["networking.service"] = true
	cfg := routerConfig()
	cfg.System.NetworkBackend = "ifupdown"
	s := New(r, nil)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	r.masked["systemd-networkd.socket"] = false
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("unmasked networkd socket passed ifupdown Health")
	}
}

func TestApplyNetOSAndSwitchToNetworkd(t *testing.T) {
	useTemporaryPaths(t)
	r := newBackendUnitRunner()
	r.active["systemd-networkd.service"] = true
	r.enabled["systemd-networkd.service"] = true
	cfg := routerConfig()
	cfg.System.NetworkBackend = "netos"
	s := New(r, nil)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(waitOnlineDropIn); err != nil {
		t.Fatalf("netos wait-online drop-in: %v", err)
	}
	cfg.System.NetworkBackend = "networkd"
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(waitOnlineDropIn); !os.IsNotExist(err) {
		t.Fatalf("networkd retained netos wait-online drop-in: %v", err)
	}
}

func TestApplyNetOSColdStartsInstalledNetworkdWithPassiveFiles(t *testing.T) {
	useTemporaryPaths(t)
	r := newBackendUnitRunner()
	cfg := routerConfig()
	cfg.System.NetworkBackend = "netos"
	s := New(r, nil)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if !r.active["systemd-networkd.service"] || !r.enabled["systemd-networkd.service"] {
		t.Fatalf("networkd was not activated: active=%v enabled=%v", r.active, r.enabled)
	}
	for _, name := range managedInterfaces(cfg) {
		if _, err := os.Stat(filepath.Join(networkdDir, networkdPrefix+name+".network")); err != nil {
			t.Fatalf("passive file for %s: %v", name, err)
		}
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
}

func TestApplyIfupdownAndCleanRepeat(t *testing.T) {
	useTemporaryPaths(t)
	r := newBackendUnitRunner()
	r.active["systemd-networkd.service"] = true
	r.enabled["systemd-networkd.service"] = true
	r.active["systemd-networkd.socket"] = true
	r.enabled["systemd-networkd.socket"] = true
	cfg := routerConfig()
	cfg.System.NetworkBackend = "ifupdown"
	s := New(r, nil)
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	r.commands = nil
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	for _, command := range r.commands {
		for _, mutation := range []string{" reload", " restart", " enable", " start", " stop", " mask", " unmask", " disable"} {
			if strings.Contains(command, mutation) {
				t.Fatalf("clean ifupdown Apply mutated runtime: %s", command)
			}
		}
	}
}

func TestNetworkManagerCreateRemoveAndAbsentUnit(t *testing.T) {
	useTemporaryPaths(t)
	r := newBackendUnitRunner()
	r.present["NetworkManager.service"] = true
	r.active["NetworkManager.service"] = true
	s := New(r, nil)
	if err := s.syncNetworkManager(context.Background(), []string{"eth1", "eth0"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(nmConfPath)
	if err != nil || !strings.Contains(string(data), "interface-name:eth1;interface-name:eth0") {
		t.Fatalf("created NetworkManager file = %q, %v", data, err)
	}
	if err := s.syncNetworkManager(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(nmConfPath); !os.IsNotExist(err) {
		t.Fatalf("empty ownership retained NetworkManager file: %v", err)
	}
	delete(r.present, "NetworkManager.service")
	if err := os.MkdirAll(filepath.Dir(nmConfPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nmConfPath, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.syncNetworkManager(context.Background(), []string{"eth0"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(nmConfPath); !os.IsNotExist(err) {
		t.Fatalf("absent NetworkManager retained stale file: %v", err)
	}
}

func TestPublicNamePlanAndRenderForAllBackends(t *testing.T) {
	r := newBackendUnitRunner()
	s := New(r, nil)
	if s.Name() != "netconf" {
		t.Fatalf("Name = %q", s.Name())
	}
	old := routerConfig()
	for _, backend := range []string{"ifupdown", "networkd", "netos", ""} {
		cfg := routerConfig()
		cfg.System.NetworkBackend = backend
		if out, err := RenderFor(cfg); err != nil || out == "" {
			t.Fatalf("RenderFor(%q) = %q, %v", backend, out, err)
		}
		actions, err := s.Plan(old, cfg)
		if err != nil || len(actions) != 1 {
			t.Fatalf("Plan(%q) = %#v, %v", backend, actions, err)
		}
	}
	cfg := routerConfig()
	cfg.System.NetworkBackend = "bogus"
	if _, err := RenderFor(cfg); err == nil {
		t.Fatal("unknown backend rendered successfully")
	}
}
