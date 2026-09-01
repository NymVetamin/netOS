package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type failingRunner struct{ err error }

func (r *failingRunner) Run(context.Context, string, ...string) (string, error) {
	return "", r.err
}

func (r *failingRunner) RunInput(context.Context, string, string, ...string) (string, error) {
	return "", r.err
}

// Отсутствующий юнит для Disable — уже достигнутая цель, а не сбой. Пропущенная
// формулировка роняет всё применение и не даёт netosd запуститься: ровно так
// сломался запуск, когда unbound выбран не был, а его юнита ещё не было.
func TestDisableTreatsMissingUnitAsSuccess(t *testing.T) {
	messages := []string{
		"systemctl disable --now netos-unbound.service: exit status 1: Failed to disable unit: Unit netos-unbound.service does not exist",
		"systemctl disable --now x.service: exit status 5: Unit x.service not loaded.",
		"systemctl disable --now x.service: No such file or directory",
		"systemctl disable --now x.service: Unit x.service not found.",
		"systemctl is-enabled x.service: Unit x.service could not be found.",
		"systemctl is-enabled x.service: not-found",
	}
	for _, msg := range messages {
		s := NewSystemd(&failingRunner{err: errors.New(msg)})
		if err := s.Disable(context.Background(), "x.service"); err != nil {
			t.Errorf("отсутствующий юнит принят за ошибку: %v", err)
		}
	}
}

func TestIsDisabledAcceptsMissingUnit(t *testing.T) {
	s := NewSystemd(&failingRunner{err: errors.New("Unit optional.service could not be found")})
	if !s.IsDisabled(context.Background(), "optional.service") {
		t.Fatal("missing optional unit was reported as enabled")
	}
}

func TestDisableReportsRealFailure(t *testing.T) {
	s := NewSystemd(&failingRunner{err: errors.New("Failed to disable unit: Access denied")})
	if err := s.Disable(context.Background(), "x.service"); err == nil {
		t.Fatal("настоящая ошибка отключения потеряна")
	}
}

// scriptedRunner отвечает по командам, чтобы можно было изобразить службу,
// которая переживает disable.
type scriptedRunner struct {
	commands []string
	active   bool
}

func (r *scriptedRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	switch {
	case strings.HasPrefix(command, "systemctl is-active"):
		if r.active {
			return "active\n", nil
		}
		return "inactive\n", nil
	case strings.HasPrefix(command, "systemctl stop"):
		// Только stop действительно останавливает: так ведут себя службы,
		// унаследованные от SysV.
		r.active = false
	}
	return "", nil
}

func (r *scriptedRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

// systemctl disable для службы, унаследованной от SysV, перенаправляется в
// update-rc.d и демона не останавливает — даже с --now. Без отдельного stop
// чужой демон остался бы висеть на порту, который нужен netOS.
func TestDisableAlsoStopsSysVService(t *testing.T) {
	r := &scriptedRunner{active: true}
	if err := NewSystemd(r).Disable(context.Background(), "xl2tpd.service"); err != nil {
		t.Fatal(err)
	}
	var stopped bool
	for _, c := range r.commands {
		if strings.HasPrefix(c, "systemctl stop xl2tpd.service") {
			stopped = true
		}
	}
	if !stopped {
		t.Fatalf("остановка не выполнялась: %v", r.commands)
	}
	if r.active {
		t.Fatal("служба осталась работать")
	}
}

// Уже погашенный юнит не трогаем. netOS гасит чужие службы при каждом
// применении конфигурации, и почти всегда они давно погашены; но systemctl
// disable для службы, унаследованной от SysV, заставляет systemd прогнать все
// генераторы системы, а их предупреждения заполняют журнал.
func TestDisableSkipsUnitThatIsAlreadyOff(t *testing.T) {
	r := &statefulRunner{active: "inactive", enabled: "disabled"}
	if err := NewSystemd(r).Disable(context.Background(), "isc-dhcp-server.service"); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.commands {
		if strings.HasPrefix(c, "systemctl disable") || strings.HasPrefix(c, "systemctl stop") {
			t.Fatalf("погашенный юнит трогали зря: %v", r.commands)
		}
	}
}

// Включённый юнит гасим, даже если он сейчас не работает: иначе он поднимется
// при следующей загрузке и подерётся за порт с демоном netOS.
func TestDisableStillDisablesEnabledButStoppedUnit(t *testing.T) {
	r := &statefulRunner{active: "inactive", enabled: "enabled"}
	if err := NewSystemd(r).Disable(context.Background(), "unbound-resolvconf.service"); err != nil {
		t.Fatal(err)
	}
	var disabled bool
	for _, c := range r.commands {
		if strings.HasPrefix(c, "systemctl disable unbound-resolvconf.service") {
			disabled = true
		}
	}
	if !disabled {
		t.Fatalf("включённый юнит остался включённым: %v", r.commands)
	}
}

// statefulRunner отвечает заданными состояниями на опрос и записывает всё,
// что было вызвано.
type statefulRunner struct {
	commands []string
	active   string
	enabled  string
}

func (r *statefulRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	switch {
	case strings.HasPrefix(command, "systemctl is-active"):
		return r.active + "\n", nil
	case strings.HasPrefix(command, "systemctl is-enabled"):
		return r.enabled + "\n", nil
	}
	r.commands = append(r.commands, command)
	return "", nil
}

func (r *statefulRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

// Если после всего служба всё ещё работает, молчать нельзя: она держит порт.
func TestDisableReportsServiceThatSurvives(t *testing.T) {
	r := &scriptedRunner{active: true}
	// Изображаем службу, которую не берёт даже stop.
	stubborn := &stubbornRunner{scriptedRunner: r}
	if err := NewSystemd(stubborn).Disable(context.Background(), "x.service"); err == nil {
		t.Fatal("выжившая служба принята за остановленную")
	}
}

type stubbornRunner struct{ *scriptedRunner }

func (r *stubbornRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	if strings.HasPrefix(command, "systemctl is-active") {
		return "active\n", nil
	}
	r.commands = append(r.commands, command)
	return "", nil
}

func (r *stubbornRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

// Штатный юнит успевает стартовать из postinst пакета и упасть на порту,
// который уже держит netOS. Погашенный, он навсегда остаётся в состоянии
// failed: systemctl показывает красную строку, а вся система — degraded, хотя
// ничего не сломано. Администратор идёт искать несуществующую поломку.
func TestDisableClearsFailedStateOfTheUnit(t *testing.T) {
	r := &scriptedRunner{active: true}
	if err := NewSystemd(r).Disable(context.Background(), "dnsmasq.service"); err != nil {
		t.Fatal(err)
	}
	var cleared bool
	for _, c := range r.commands {
		if strings.HasPrefix(c, "systemctl reset-failed dnsmasq.service") {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("состояние failed не сброшено: %v", r.commands)
	}
}

type recordingRunner struct {
	commands []string
	output   string
	err      error
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.commands = append(r.commands, name+" "+strings.Join(args, " "))
	return r.output, r.err
}

func (r *recordingRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestSystemdCommandWrappersAndActiveUnits(t *testing.T) {
	r := &recordingRunner{}
	s := NewSystemd(r)
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"start":             func() error { return s.Start(ctx, "x.service") },
		"stop":              func() error { return s.Stop(ctx, "x.service") },
		"restart":           func() error { return s.Restart(ctx, "x.service") },
		"reload":            func() error { return s.Reload(ctx, "x.service") },
		"reload-or-restart": func() error { return s.ReloadOrRestart(ctx, "x.service") },
		"enable":            func() error { return s.Enable(ctx, "x.service") },
		"daemon-reload":     func() error { return s.DaemonReload(ctx) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err != nil {
				t.Fatal(err)
			}
		})
	}
	joined := strings.Join(r.commands, "\n")
	for _, want := range []string{
		"systemctl start x.service", "systemctl stop x.service", "systemctl restart x.service",
		"systemctl reload x.service", "systemctl reload-or-restart x.service",
		"systemctl enable x.service", "systemctl daemon-reload",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing command %q in %v", want, r.commands)
		}
	}

	r.output = "netos-a.service loaded active running A\nnetos-b.service loaded active running B\n\n"
	units := s.ActiveUnits(ctx, "netos-*.service")
	if strings.Join(units, ",") != "netos-a.service,netos-b.service" {
		t.Fatalf("active units=%v", units)
	}
	r.err = errors.New("systemctl unavailable")
	if units := s.ActiveUnits(ctx, "netos-*.service"); units != nil {
		t.Fatalf("failed ActiveUnits=%v", units)
	}
	if err := s.Start(ctx, "x.service"); err == nil {
		t.Fatal("systemctl failure was lost")
	}
}

type packageRunner struct {
	installed  map[string]bool
	commands   []string
	aptErr     error
	policyPath string
	sawPolicy  bool
	policyMode os.FileMode
}

func (r *packageRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.commands = append(r.commands, name+" "+strings.Join(args, " "))
	if name == "dpkg-query" {
		pkg := args[len(args)-1]
		if r.installed[pkg] {
			return "install ok installed", nil
		}
		return "", errors.New("not installed")
	}
	if name == "apt-get" {
		if info, err := os.Stat(r.policyPath); err == nil {
			r.sawPolicy = true
			r.policyMode = info.Mode().Perm()
		}
		return "", r.aptErr
	}
	return "", nil
}

func (r *packageRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func withTestPolicyPath(t *testing.T) string {
	t.Helper()
	old := PolicyRCPath
	PolicyRCPath = filepath.Join(t.TempDir(), "policy-rc.d")
	t.Cleanup(func() { PolicyRCPath = old })
	return PolicyRCPath
}

func TestPackagesInstalledEnsureAndPolicyCleanup(t *testing.T) {
	path := withTestPolicyPath(t)
	r := &packageRunner{installed: map[string]bool{"present": true}, policyPath: path}
	p := NewPackages(r)
	if !p.Installed(context.Background(), "present") || p.Installed(context.Background(), "missing") {
		t.Fatal("Installed returned wrong package state")
	}
	installed, err := p.Ensure(context.Background(), "present", "missing", "also-missing")
	if err != nil || strings.Join(installed, ",") != "missing,also-missing" {
		t.Fatalf("installed=%v err=%v", installed, err)
	}
	if !r.sawPolicy {
		t.Fatal("apt ran without temporary policy-rc.d")
	}
	if runtime.GOOS != "windows" && r.policyMode != 0o755 {
		t.Fatalf("policy mode=%v", r.policyMode)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("temporary policy remains: %v", err)
	}
	joined := strings.Join(r.commands, "\n")
	if !strings.Contains(joined, "apt-get -o DPkg::Lock::Timeout=60 install -y --no-install-recommends missing also-missing") {
		t.Fatalf("unexpected commands: %v", r.commands)
	}

	r.commands = nil
	if got, err := p.Ensure(context.Background(), "present"); err != nil || got != nil {
		t.Fatalf("all-present result=%v err=%v", got, err)
	}
	for _, command := range r.commands {
		if strings.HasPrefix(command, "apt-get ") {
			t.Fatalf("apt called for installed package: %v", r.commands)
		}
	}
}

func TestPackagesEnsureCleansPolicyAfterAptFailure(t *testing.T) {
	path := withTestPolicyPath(t)
	r := &packageRunner{installed: map[string]bool{}, aptErr: errors.New("apt failed"), policyPath: path}
	if _, err := NewPackages(r).Ensure(context.Background(), "missing"); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("apt failure=%v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("temporary policy remains after error: %v", err)
	}
}

func TestPackagesPreservesExistingPolicy(t *testing.T) {
	path := withTestPolicyPath(t)
	const foreign = "#!/bin/sh\nexit 0\n"
	if err := os.WriteFile(path, []byte(foreign), 0o700); err != nil {
		t.Fatal(err)
	}
	r := &packageRunner{installed: map[string]bool{}, policyPath: path}
	if _, err := NewPackages(r).Ensure(context.Background(), "missing"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != foreign {
		t.Fatalf("foreign policy changed: %q err=%v", data, err)
	}
}
