package manage

import (
	"bytes"
	"context"
	"errors"
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
	if !contains(commands[1].env, "NETOS_VERSION=v1.2.4") ||
		!contains(commands[1].env, "NETOS_ACTION=upgrade") {
		t.Fatalf("версия не передана установщику: %#v", commands[1].env)
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
