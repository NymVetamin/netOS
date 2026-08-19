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
