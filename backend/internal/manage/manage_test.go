package manage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testManager() (*Manager, *bytes.Buffer) {
	out := &bytes.Buffer{}
	m := New("v1.2.3")
	m.In = strings.NewReader("")
	m.Out, m.Err = out, out
	m.EUID = func() int { return 0 }
	m.Run = func(context.Context, command) error { return nil }
	m.Output = func(context.Context, string, ...string) (string, error) { return "", nil }
	return m, out
}

// sandbox уводит все пути менеджера во временный каталог. Тесты удаления и
// сброса выполняют настоящие os.Remove, и без этого прогон под root на машине
// разработки снёс бы установленный там netOS.
func sandbox(t *testing.T, m *Manager) {
	t.Helper()
	root := t.TempDir()
	m.Root = root
	m.StateDir = filepath.Join(root, "var/lib/netos")
	m.ConfigDir = filepath.Join(root, "etc/netos")
	m.LogDir = filepath.Join(root, "var/log/netos")
	m.BackupDir = filepath.Join(root, "var/backups/netos")
	m.Binary = filepath.Join(root, "usr/local/bin/netosd")
	m.CLI = filepath.Join(root, "usr/local/bin/netos")
	m.Unit = filepath.Join(root, "etc/systemd/system/netosd.service")
}

func TestHelpUsesPublicNetosCommands(t *testing.T) {
	m, out := testManager()
	if err := m.Execute(context.Background(), []string{"help"}); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"netos update", "netos reinstall", "netos reset", "netos uninstall"} {
		if !strings.Contains(out.String(), command) {
			t.Fatalf("справка не содержит %q", command)
		}
	}
}

func TestVersion(t *testing.T) {
	m, out := testManager()
	if err := m.Execute(context.Background(), []string{"version"}); err != nil {
		t.Fatal(err)
	}
	if out.String() != "netOS v1.2.3\n" {
		t.Fatalf("неожиданный вывод: %q", out.String())
	}
}

func TestMutationRequiresRoot(t *testing.T) {
	m, _ := testManager()
	m.EUID = func() int { return 1000 }
	if err := m.Execute(context.Background(), []string{"update"}); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("update без root вернул %v", err)
	}
}

func TestResetWithoutConfirmationDoesNothing(t *testing.T) {
	m, out := testManager()
	calls := 0
	m.Run = func(context.Context, command) error { calls++; return nil }
	if err := m.Execute(context.Background(), []string{"reset"}); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("после отказа выполнено команд: %d", calls)
	}
	if !strings.Contains(out.String(), "Отменено") {
		t.Fatalf("нет сообщения об отмене: %q", out.String())
	}
}

func TestVersionArgumentRejectsShellSyntax(t *testing.T) {
	if _, err := positionalVersion([]string{"v1.0;reboot"}); err == nil {
		t.Fatal("опасная версия принята")
	}
}

func TestUpdatePassesRequestedVersionToInstaller(t *testing.T) {
	m, _ := testManager()
	var commands []command
	m.Run = func(_ context.Context, spec command) error {
		commands = append(commands, spec)
		return nil
	}
	if err := m.Execute(context.Background(), []string{"update", "v1.2.4"}); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 2 || commands[1].name != "bash" {
		t.Fatalf("неожиданные команды: %#v", commands)
	}
	if !contains(commands[1].env, "NETOS_VERSION=v1.2.4") {
		t.Fatalf("версия не передана установщику: %#v", commands[1].env)
	}
}

// reinstall — синоним update, и это должно оставаться проверяемым фактом,
// а не обещанием в тексте справки.
func TestReinstallBehavesLikeUpdate(t *testing.T) {
	m, _ := testManager()
	var commands []command
	m.Run = func(_ context.Context, spec command) error {
		commands = append(commands, spec)
		return nil
	}
	if err := m.Execute(context.Background(), []string{"reinstall", "v1.2.4"}); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 2 || commands[1].name != "bash" ||
		!contains(commands[1].env, "NETOS_VERSION=v1.2.4") {
		t.Fatalf("reinstall расходится с update: %#v", commands)
	}
}

func TestUpdateFallsBackToSourceWhenReleaseIsMissing(t *testing.T) {
	m, _ := testManager()
	m.Output = func(context.Context, string, ...string) (string, error) {
		return "", errors.New("not found")
	}
	var installer command
	m.Run = func(_ context.Context, spec command) error {
		if spec.name == "bash" {
			installer = spec
		}
		return nil
	}
	if err := m.Execute(context.Background(), []string{"update"}); err != nil {
		t.Fatal(err)
	}
	if !contains(installer.env, "NETOS_FROM_SOURCE=1") {
		t.Fatalf("сборка из исходников не включена: %#v", installer.env)
	}
}

func TestRemovePolicyRulesOnlyTouchesNetOSRange(t *testing.T) {
	m, _ := testManager()
	m.Output = func(context.Context, string, ...string) (string, error) {
		return "0: from all lookup local\n20100: from 10.0.0.0/8 lookup vpn\n32766: from all lookup main\n", nil
	}
	var commands []command
	m.Run = func(_ context.Context, spec command) error {
		commands = append(commands, spec)
		return nil
	}
	m.removePolicyRules(context.Background())
	if len(commands) != 1 || !contains(commands[0].args, "20100") {
		t.Fatalf("удалены неверные правила: %#v", commands)
	}
}

// systemctl stop отдаёт код 5 на незагруженный юнит. Если считать это ошибкой,
// удаление после однажды прерванной попытки уже никогда не доработает.
func TestUninstallProceedsWhenUnitIsNotLoaded(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	var commands []command
	m.Run = func(_ context.Context, spec command) error {
		commands = append(commands, spec)
		if spec.name == "systemctl" && len(spec.args) > 0 && spec.args[0] == "stop" {
			return errors.New("Unit netosd.service not loaded")
		}
		return nil
	}
	m.Output = func(_ context.Context, name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) > 0 && args[0] == "is-active" {
			return "unknown\n", errors.New("exit status 4")
		}
		return "", nil
	}
	if err := m.uninstall(context.Background(), true, true); err != nil {
		t.Fatalf("удаление прервалось на незагруженном юните: %v", err)
	}
	var cleared bool
	for _, c := range commands {
		if c.name == "iptables-restore" {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("удаление не дошло до очистки правил: %#v", commands)
	}
}

func TestStopDaemonReportsRealFailure(t *testing.T) {
	m, _ := testManager()
	m.Run = func(context.Context, command) error { return errors.New("job failed") }
	m.Output = func(context.Context, string, ...string) (string, error) { return "active\n", nil }
	if err := m.stopDaemon(context.Background()); err == nil {
		t.Fatal("остановка работающей службы провалилась, но ошибка потеряна")
	}
}

func TestLogsRequireRoot(t *testing.T) {
	m, _ := testManager()
	m.EUID = func() int { return 1000 }
	if err := m.Execute(context.Background(), []string{"logs"}); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("logs без root вернул %v", err)
	}
}

// Удаление обязано возвращать машину в исходное состояние. Оставленное
// описание сегментов пережило бы netOS: система продолжала бы создавать
// бриджи и адреса, которых больше никто не обслуживает.
func TestUninstallRemovesGeneratedNetworkConfig(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	m.Run = func(context.Context, command) error { return nil }

	ifupdown := filepath.Join(m.Root, "etc/network/interfaces.d/netos.conf")
	networkd := filepath.Join(m.Root, "etc/systemd/network/05-netos-br-lan.network")
	foreign := filepath.Join(m.Root, "etc/systemd/network/10-all.network")
	for _, path := range []string{ifupdown, networkd, foreign} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := m.uninstall(context.Background(), true, true); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{ifupdown, networkd} {
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("после удаления остался %s", path)
		}
	}
	// Чужие файлы не наши, и трогать их нельзя.
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("удалён чужой файл конфигурации сети: %v", err)
	}
}
