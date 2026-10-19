package netconf

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unitRunner отвечает на systemctl заранее заданными строками.
type unitRunner struct {
	active  string
	enabled string
}

func (r unitRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	if name != "systemctl" || len(args) == 0 {
		return "", nil
	}
	switch args[0] {
	case "is-active":
		return r.active, nil
	case "is-enabled":
		if r.enabled == "" {
			return "", fmt.Errorf("Failed to get unit file state: No such file or directory")
		}
		return r.enabled, nil
	}
	return "", nil
}

func (r unitRunner) RunInput(_ context.Context, _ string, _ string, _ ...string) (string, error) {
	return "", nil
}

type recordingLogger struct{ warnings []string }

func (l *recordingLogger) Infof(format string, args ...any) {}
func (l *recordingLogger) Warnf(format string, args ...any) {
	l.warnings = append(l.warnings, fmt.Sprintf(format, args...))
}

// conflictingIfupdown создаёт чужое описание интерфейса, которым управляет
// netOS, и уводит туда пути подсистемы.
func conflictingIfupdown(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "eth0"),
		[]byte("auto eth0\niface eth0 inet dhcp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldDir, oldMain := ifupdownDir, ifupdownMain
	ifupdownDir = dir
	ifupdownMain = filepath.Join(dir, "interfaces")
	t.Cleanup(func() { ifupdownDir, ifupdownMain = oldDir, oldMain })
}

// Запись в /etc/network/interfaces.d при выключенной и неработающей
// networking.service не делает ничего и не сделает после перезагрузки: читать
// её некому. Требовать её убрать — значит звать администратора чинить то, что
// не сломано, и делать это при каждом применении конфигурации.
func TestNoIfupdownWarningWhenNetworkingIsOff(t *testing.T) {
	conflictingIfupdown(t)
	logger := &recordingLogger{}
	s := New(unitRunner{active: "inactive"}, logger)

	s.warnAboutIfupdown(context.Background(), routerConfig())

	if len(logger.warnings) != 0 {
		t.Fatalf("предупреждение о безобидном файле: %v", logger.warnings)
	}
	if conflicts := s.IfupdownConflicts(context.Background(), routerConfig()); len(conflicts) != 0 {
		t.Fatalf("панель получила безобидный конфликт: %v", conflicts)
	}
}

// Работающая или включённая служба — другое дело: при загрузке она поднимет
// второй клиент DHCP на интерфейсе netOS, и об этом надо сказать.
func TestIfupdownWarningWhenNetworkingIsEnabled(t *testing.T) {
	conflictingIfupdown(t)
	logger := &recordingLogger{}
	s := New(unitRunner{active: "inactive", enabled: "enabled"}, logger)

	s.warnAboutIfupdown(context.Background(), routerConfig())

	if len(logger.warnings) != 1 || !strings.Contains(logger.warnings[0], "eth0") {
		t.Fatalf("конфликт не назван: %v", logger.warnings)
	}
	if conflicts := s.IfupdownConflicts(context.Background(), routerConfig()); len(conflicts) != 1 || !strings.Contains(conflicts[0], "eth0") {
		t.Fatalf("панель не получила конфликт: %v", conflicts)
	}
}

// Applyы идут при каждом изменении конфигурации. Повторять одно и то же
// предупреждение на каждом — значит утопить в нём журнал.
func TestIfupdownWarningIsNotRepeated(t *testing.T) {
	conflictingIfupdown(t)
	logger := &recordingLogger{}
	s := New(unitRunner{active: "active"}, logger)

	s.warnAboutIfupdown(context.Background(), routerConfig())
	s.warnAboutIfupdown(context.Background(), routerConfig())
	s.warnAboutIfupdown(context.Background(), routerConfig())

	if len(logger.warnings) != 1 {
		t.Fatalf("предупреждение повторено %d раз: %v", len(logger.warnings), logger.warnings)
	}
}

func TestIfupdownQueriesServicesOnlyForPotentialConflicts(t *testing.T) {
	conflictingIfupdown(t)
	foreign := filepath.Join(ifupdownDir, "eth0")
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	oldOwn := ifupdownPath
	ifupdownPath = filepath.Join(ifupdownDir, "netos")
	t.Cleanup(func() { ifupdownPath = oldOwn })
	if err := os.WriteFile(ifupdownPath, []byte("auto eth0\niface eth0 inet dhcp\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ifupdownMain, []byte("auto lo eth0.100\niface eth0.100 inet dhcp\n# auto eth0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r := &backendUnitRunner{active: map[string]bool{}, enabled: map[string]bool{}}
	s := New(r, nil)
	check := func(want int) {
		t.Helper()
		if got := s.IfupdownConflicts(context.Background(), routerConfig()); len(got) != want {
			t.Fatalf("conflicts=%v, want %d", got, want)
		}
	}
	check(0)
	if len(r.commands) != 0 {
		t.Fatalf("no potential conflict but executed %v", r.commands)
	}
	if err := os.WriteFile(foreign, []byte("auto eth0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	check(0)
	if len(r.commands) != 2 {
		t.Fatalf("potential conflict must check active/enabled: %v", r.commands)
	}
	r.enabled["networking.service"] = true
	check(1)
	r.enabled["networking.service"] = false
	r.active["networking.service"] = true
	check(1)
	r.active["networking.service"] = false
	check(0)
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	r.commands = nil
	check(0)
	if len(r.commands) != 0 {
		t.Fatalf("removed declaration still queried services: %v", r.commands)
	}
}
