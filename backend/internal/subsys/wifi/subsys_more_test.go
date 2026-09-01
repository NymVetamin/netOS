package wifi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

type transientWiFiRunner struct {
	base      *fakeRunner
	device    string
	remaining int
}

func (r *transientWiFiRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	if command == "iw dev "+r.device+" info" && r.remaining > 0 {
		r.remaining--
		return "", nil
	}
	return r.base.Run(ctx, name, args...)
}

func (r *transientWiFiRunner) RunInput(ctx context.Context, input, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func testWiFiSubsystem(t *testing.T, runner *fakeRunner) *Subsystem {
	t.Helper()
	root := t.TempDir()
	s := New(runner, filepath.Join(root, "state"))
	s.UnitDir = filepath.Join(root, "units")
	return s
}

func TestIdentityPlanCleanChangesAndLiveDrift(t *testing.T) {
	runner := &fakeRunner{}
	s := testWiFiSubsystem(t, runner)
	if s.Name() != "wifi" {
		t.Fatalf("name=%q", s.Name())
	}
	empty := config.Default()
	if actions, err := s.Plan(nil, empty); err != nil || len(actions) != 0 {
		t.Fatalf("empty initial plan=%+v err=%v", actions, err)
	}
	cfg := wifiConfig()
	actions, err := s.Plan(empty, cfg)
	if err != nil || len(actions) != 1 || actions[0].Kind != "restart" || !actions[0].Disruptive {
		t.Fatalf("create plan=%+v err=%v", actions, err)
	}
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if actions, err = s.Plan(cfg, cfg); err != nil || len(actions) != 0 {
		t.Fatalf("clean plan=%+v err=%v", actions, err)
	}
	runner.outputs = map[string]string{"iw dev wlan0-n1 info": "Interface wlan0-n1\n\tssid wrong\n\ttype AP\n\tchannel 36"}
	actions, err = s.Plan(cfg, cfg)
	if err != nil || len(actions) != 1 || !strings.Contains(actions[0].Detail, "расхождения") {
		t.Fatalf("drift plan=%+v err=%v", actions, err)
	}
}

func TestApplyIsExactNoOpAndRepairsRuntimeDrift(t *testing.T) {
	runner := &fakeRunner{}
	s := testWiFiSubsystem(t, runner)
	cfg := wifiConfig()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	conf, unit := s.paths(cfg.WiFi[0])
	confBefore, _ := os.Stat(conf)
	unitBefore, _ := os.Stat(unit)
	time.Sleep(20 * time.Millisecond)
	runner.commands = nil
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	for _, command := range runner.commands {
		for _, mutation := range []string{" set txpower ", " daemon-reload", " enable ", " restart ", " stop ", " disable "} {
			if strings.Contains(" "+command+" ", mutation) {
				t.Fatalf("clean Apply mutated Wi-Fi: %s", command)
			}
		}
	}
	confAfter, _ := os.Stat(conf)
	unitAfter, _ := os.Stat(unit)
	if !confBefore.ModTime().Equal(confAfter.ModTime()) || !unitBefore.ModTime().Equal(unitAfter.ModTime()) {
		t.Fatal("clean Apply rewrote hostapd artifacts")
	}

	runner.outputs = map[string]string{"iw dev wlan0-n1 info": ""}
	runner.commands = nil
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(runner.commands, "\n"), "systemctl restart ") {
		t.Fatal("missing secondary BSS did not trigger restart")
	}
}

func TestForeignArtifactsAreRejectedBeforeOldRadioRemoval(t *testing.T) {
	runner := &fakeRunner{}
	s := testWiFiSubsystem(t, runner)
	old := wifiConfig()
	if err := s.Apply(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	next := wifiConfig()
	next.WiFi[0].ID = "other-radio"
	next.WiFi[0].Device = "wlan1"
	_, foreignUnit := s.paths(next.WiFi[0])
	if err := os.MkdirAll(filepath.Dir(foreignUnit), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreignUnit, []byte("foreign"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner.commands = nil
	err := s.Apply(context.Background(), next)
	if err == nil || !strings.Contains(err.Error(), "не принадлежат") {
		t.Fatalf("foreign unit accepted: %v", err)
	}
	for _, command := range runner.commands {
		if strings.HasPrefix(command, "systemctl stop ") {
			t.Fatalf("old working radio removed before desired preflight: %s", command)
		}
	}
}

func TestHealthChecksOwnershipFilesEnableAndExactRuntime(t *testing.T) {
	runner := &fakeRunner{}
	s := testWiFiSubsystem(t, runner)
	cfg := wifiConfig()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	t.Run("ownership", func(t *testing.T) {
		if err := os.WriteFile(s.ownedPath(), []byte("[]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := s.Health(context.Background(), cfg); err == nil {
			t.Fatal("ownership drift accepted")
		}
		if err := s.writeOwned([]ownedRadio{{ID: cfg.WiFi[0].ID, Unit: unitName(cfg.WiFi[0])}}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("config", func(t *testing.T) {
		conf, _ := s.paths(cfg.WiFi[0])
		original, _ := os.ReadFile(conf)
		if err := os.WriteFile(conf, []byte("corrupt"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := s.Health(context.Background(), cfg); err == nil {
			t.Fatal("config drift accepted")
		}
		if err := os.WriteFile(conf, original, 0o600); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("enabled", func(t *testing.T) {
		runner.enabled = false
		if err := s.Health(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "не включён") {
			t.Fatalf("disabled unit accepted: %v", err)
		}
		runner.enabled = true
	})

	for _, tc := range []struct {
		name, output string
	}{
		{"device", "Interface wlan0-evil\n\tssid netOS\n\ttype AP\n\tchannel 36\n\ttxpower 18.00 dBm"},
		{"type", "Interface wlan0\n\tssid netOS\n\ttype managed\n\tchannel 36\n\ttxpower 18.00 dBm"},
		{"channel", "Interface wlan0\n\tssid netOS\n\ttype AP\n\tchannel 136\n\ttxpower 18.00 dBm"},
		{"ssid", "Interface wlan0\n\tssid netOS evil\n\ttype AP\n\tchannel 36\n\ttxpower 18.00 dBm"},
		{"txpower", "Interface wlan0\n\tssid netOS\n\ttype AP\n\tchannel 36\n\ttxpower 17.00 dBm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner.outputs = map[string]string{"iw dev wlan0 info": tc.output}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			if err := s.Health(ctx, cfg); err == nil {
				t.Fatal("runtime drift accepted")
			}
			runner.outputs = nil
		})
	}
}

func TestHealthHonorsCancellationWithoutWaitingNineSeconds(t *testing.T) {
	runner := &fakeRunner{}
	s := testWiFiSubsystem(t, runner)
	cfg := wifiConfig()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	runner.outputs = map[string]string{"iw dev wlan0-n1 info": ""}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	err := s.Health(ctx, cfg)
	if !errors.Is(err, context.Canceled) || time.Since(started) > 250*time.Millisecond {
		t.Fatalf("cancellation=%v elapsed=%v", err, time.Since(started))
	}
}

func TestCleanupFailureAndResidualStatePreserveOwnership(t *testing.T) {
	runner := &fakeRunner{}
	s := testWiFiSubsystem(t, runner)
	cfg := wifiConfig()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	unit := unitName(cfg.WiFi[0])
	runner.errors = map[string]error{"systemctl stop " + unit: errors.New("stop denied")}
	if err := s.Apply(context.Background(), config.Default()); err == nil || !strings.Contains(err.Error(), "stop denied") {
		t.Fatalf("cleanup error ignored: %v", err)
	}
	owned, _ := s.readOwned()
	if len(owned) != 1 {
		t.Fatalf("ownership lost after cleanup error: %+v", owned)
	}

	runner.errors = nil
	runner.outputs = map[string]string{"systemctl is-active " + unit: "active\n"}
	if err := s.Apply(context.Background(), config.Default()); err == nil || !strings.Contains(err.Error(), "активным") {
		t.Fatalf("residual active unit accepted: %v", err)
	}
	owned, _ = s.readOwned()
	if len(owned) != 1 {
		t.Fatalf("ownership lost with residual unit: %+v", owned)
	}
}

func TestNewRadioDoubleFailureIsRecordedForRetry(t *testing.T) {
	runner := &fakeRunner{}
	s := testWiFiSubsystem(t, runner)
	cfg := wifiConfig()
	unit := unitName(cfg.WiFi[0])
	runner.errors = map[string]error{
		"systemctl restart " + unit: errors.New("start failed"),
		"systemctl stop " + unit:    errors.New("cleanup failed"),
	}
	err := s.Apply(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "start failed") || !strings.Contains(err.Error(), "cleanup failed") {
		t.Fatalf("double failure=%v", err)
	}
	owned, readErr := s.readOwned()
	if readErr != nil || len(owned) != 1 || owned[0].ID != cfg.WiFi[0].ID {
		t.Fatalf("leaked object not recorded: %+v err=%v", owned, readErr)
	}
}

func TestWiFiFileModesAndOwnershipAreStable(t *testing.T) {
	runner := &fakeRunner{}
	s := testWiFiSubsystem(t, runner)
	cfg := wifiConfig()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	conf, unit := s.paths(cfg.WiFi[0])
	if runtime.GOOS != "windows" {
		for path, mode := range map[string]os.FileMode{conf: 0o600, unit: 0o644, s.ownedPath(): 0o600} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != mode {
				t.Fatalf("%s mode=%v err=%v", path, info.Mode(), err)
			}
		}
	}
}

func TestApplyRejectsRenderAndContradictoryOwnership(t *testing.T) {
	t.Run("render", func(t *testing.T) {
		cfg := wifiConfig()
		cfg.WiFi[0].SSIDs = nil
		err := testWiFiSubsystem(t, &fakeRunner{}).Apply(context.Background(), cfg)
		if err == nil || !strings.Contains(err.Error(), "нет включённых") {
			t.Fatalf("render error=%v", err)
		}
	})
	t.Run("ownership", func(t *testing.T) {
		runner := &fakeRunner{}
		s := testWiFiSubsystem(t, runner)
		cfg := wifiConfig()
		if err := s.writeOwned([]ownedRadio{{ID: cfg.WiFi[0].ID, Unit: "wrong.service"}}); err != nil {
			t.Fatal(err)
		}
		err := s.Apply(context.Background(), cfg)
		if err == nil || !strings.Contains(err.Error(), "противоречивый") {
			t.Fatalf("contradictory ownership accepted: %v", err)
		}
	})
}

func TestEveryApplyRadioCommandFailureIsReturned(t *testing.T) {
	cfg := wifiConfig()
	radio := cfg.WiFi[0]
	unit := unitName(radio)
	commands := []string{
		"iw dev wlan0 set txpower fixed 1800",
		"systemctl daemon-reload",
		"systemctl enable " + unit,
		"systemctl restart " + unit,
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			runner := &fakeRunner{errors: map[string]error{command: errors.New("injected")}}
			s := testWiFiSubsystem(t, runner)
			err := s.applyRadio(context.Background(), cfg, radio)
			if err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestApplyRadioFileWriteFailuresAreReturned(t *testing.T) {
	cfg := wifiConfig()
	radio := cfg.WiFi[0]
	t.Run("config", func(t *testing.T) {
		root := t.TempDir()
		blocker := filepath.Join(root, "blocker")
		if err := os.WriteFile(blocker, []byte("file"), 0o600); err != nil {
			t.Fatal(err)
		}
		s := New(&fakeRunner{}, filepath.Join(blocker, "state"))
		s.UnitDir = filepath.Join(root, "units")
		if err := s.applyRadio(context.Background(), cfg, radio); err == nil {
			t.Fatal("config write error ignored")
		}
	})
	t.Run("unit", func(t *testing.T) {
		root := t.TempDir()
		unitBlocker := filepath.Join(root, "unit-blocker")
		if err := os.WriteFile(unitBlocker, []byte("file"), 0o600); err != nil {
			t.Fatal(err)
		}
		s := New(&fakeRunner{}, filepath.Join(root, "state"))
		s.UnitDir = filepath.Join(unitBlocker, "units")
		if err := s.applyRadio(context.Background(), cfg, radio); err == nil {
			t.Fatal("unit write error ignored")
		}
	})
}

func TestRemoveEveryFailureAndMissingObjects(t *testing.T) {
	cfg := wifiConfig()
	item := ownedRadio{ID: cfg.WiFi[0].ID, Unit: unitName(cfg.WiFi[0])}
	for _, command := range []string{"systemctl stop " + item.Unit, "systemctl disable " + item.Unit, "systemctl daemon-reload"} {
		t.Run(command, func(t *testing.T) {
			runner := &fakeRunner{errors: map[string]error{command: errors.New("injected")}}
			s := testWiFiSubsystem(t, runner)
			if err := s.remove(context.Background(), item); err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("error=%v", err)
			}
		})
	}

	runner := &fakeRunner{errors: map[string]error{
		"systemctl stop " + item.Unit:    errors.New("unit not loaded"),
		"systemctl disable " + item.Unit: errors.New("not found"),
	}}
	if err := testWiFiSubsystem(t, runner).remove(context.Background(), item); err != nil {
		t.Fatalf("missing objects must be idempotent: %v", err)
	}
}

func TestOwnershipReadWriteErrorsAndSorting(t *testing.T) {
	dir := t.TempDir()
	s := New(&fakeRunner{}, dir)
	s.UnitDir = filepath.Join(dir, "units")
	if err := os.WriteFile(s.ownedPath(), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readOwned(); err == nil || !strings.Contains(err.Error(), "разбор") {
		t.Fatalf("malformed ownership accepted: %v", err)
	}
	if err := os.Remove(s.ownedPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.ownedPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readOwned(); err == nil {
		t.Fatal("ownership read error ignored")
	}

	cfg := wifiConfig()
	second := cfg.WiFi[0]
	second.ID, second.Device = "a-radio", "wlan1"
	cfg.WiFi = append(cfg.WiFi, second)
	radios := enabledRadios(cfg)
	if len(radios) != 2 || radios[0].ID != "a-radio" {
		t.Fatalf("enabled radios not sorted: %+v", radios)
	}
	cfg.WiFi[0].Enabled = false
	if radios = enabledRadios(cfg); len(radios) != 1 || radios[0].ID != "a-radio" {
		t.Fatalf("disabled radio retained: %+v", radios)
	}
}

func TestRadioRuntimeSkipsDisabledSSID(t *testing.T) {
	runner := &fakeRunner{active: true, enabled: true}
	s := testWiFiSubsystem(t, runner)
	radio := wifiConfig().WiFi[0]
	radio.SSIDs = append([]config.WiFiSSID{{ID: "off", SSID: "off", Enabled: false}}, radio.SSIDs...)
	ready, _ := s.radioRuntimeMatches(context.Background(), radio)
	if !ready {
		t.Fatal("disabled SSID affected runtime match")
	}
	for _, command := range runner.commands {
		if strings.Contains(command, "-n2") {
			t.Fatalf("disabled SSID consumed a BSS index: %s", command)
		}
	}
}

func TestApplyAndHealthPropagateOwnershipAndRenderErrors(t *testing.T) {
	t.Run("Apply ownership read", func(t *testing.T) {
		runner := &fakeRunner{}
		s := testWiFiSubsystem(t, runner)
		if err := os.MkdirAll(s.ownedPath(), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := s.Apply(context.Background(), config.Default()); err == nil {
			t.Fatal("Apply ignored ownership read error")
		}
	})
	t.Run("Health ownership read", func(t *testing.T) {
		runner := &fakeRunner{}
		s := testWiFiSubsystem(t, runner)
		if err := os.MkdirAll(s.ownedPath(), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := s.Health(context.Background(), config.Default()); err == nil {
			t.Fatal("Health ignored ownership read error")
		}
	})
	t.Run("applyRadio render", func(t *testing.T) {
		cfg := wifiConfig()
		cfg.WiFi[0].SSIDs = nil
		if err := testWiFiSubsystem(t, &fakeRunner{}).applyRadio(context.Background(), cfg, cfg.WiFi[0]); err == nil {
			t.Fatal("applyRadio ignored render error")
		}
	})
	t.Run("Health render", func(t *testing.T) {
		cfg := wifiConfig()
		cfg.WiFi[0].SSIDs = nil
		s := testWiFiSubsystem(t, &fakeRunner{})
		if err := s.writeOwned([]ownedRadio{{ID: cfg.WiFi[0].ID, Unit: unitName(cfg.WiFi[0])}}); err != nil {
			t.Fatal(err)
		}
		if err := s.Health(context.Background(), cfg); err == nil {
			t.Fatal("Health ignored render error")
		}
	})
}

func TestExistingRadioFailureKeepsOwnershipWithoutNewCleanup(t *testing.T) {
	runner := &fakeRunner{}
	s := testWiFiSubsystem(t, runner)
	cfg := wifiConfig()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	cfg.WiFi[0].TxPower = 19
	runner.errors = map[string]error{"iw dev wlan0 set txpower fixed 1900": errors.New("txpower failed")}
	runner.commands = nil
	if err := s.Apply(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "txpower failed") {
		t.Fatalf("existing radio error=%v", err)
	}
	for _, command := range runner.commands {
		if strings.HasPrefix(command, "systemctl stop ") {
			t.Fatalf("existing radio entered new-object cleanup: %s", command)
		}
	}
	owned, _ := s.readOwned()
	if len(owned) != 1 {
		t.Fatalf("existing ownership lost: %+v", owned)
	}
}

func TestHealthRetriesTransientBSSUntilReady(t *testing.T) {
	base := &fakeRunner{}
	s := testWiFiSubsystem(t, base)
	cfg := wifiConfig()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	s.Runner = &transientWiFiRunner{base: base, device: "wlan0-n1", remaining: 1}
	started := time.Now()
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) < 140*time.Millisecond {
		t.Fatalf("Health did not retry transient BSS: %v", time.Since(started))
	}
}

func TestRemovePropagatesFilesystemFailure(t *testing.T) {
	runner := &fakeRunner{}
	s := testWiFiSubsystem(t, runner)
	cfg := wifiConfig()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	conf, _ := s.paths(cfg.WiFi[0])
	if err := os.Remove(conf); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(conf, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(conf, "child"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := s.remove(context.Background(), ownedRadio{ID: cfg.WiFi[0].ID, Unit: unitName(cfg.WiFi[0])})
	if err == nil {
		t.Fatal("filesystem cleanup error ignored")
	}
}
