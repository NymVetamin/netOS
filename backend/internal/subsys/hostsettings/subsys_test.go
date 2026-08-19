package hostsettings

import (
	"context"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type hostRunner struct {
	commands []string
	// active подменяет ответ systemctl is-active: так проверяется поведение на
	// машине, где чужой демон действительно работает.
	active bool
}

func (r *hostRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	switch command {
	case "hostnamectl --static":
		return "router\n", nil
	case "timedatectl show --property=Timezone --value":
		return "Europe/Moscow\n", nil
	case "systemctl is-active tuned.service":
		if r.active {
			return "active\n", nil
		}
		return "inactive\n", nil
	default:
		return "", nil
	}
}

func (r *hostRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestApplyAndHealthSystemSettings(t *testing.T) {
	runner := &hostRunner{}
	s := New(runner)
	cfg := config.Default()
	cfg.System.Hostname = "router"
	cfg.System.Timezone = "Europe/Moscow"
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	for _, want := range []string{"hostnamectl set-hostname router", "timedatectl set-timezone Europe/Moscow"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("нет команды %q:\n%s", want, joined)
		}
	}
}


// netOS — единый центр истины на машине: демон дистрибутива, правящий то же,
// чем владеет netOS, обязан быть погашен. tuned на облачных образах
// переустанавливает сетевые параметры ядра и откатывает подавление IPv6 на
// аплинке уже после того, как netOS его применил.
func TestApplyStopsDaemonsThatOverrideNetOS(t *testing.T) {
	runner := &hostRunner{}
	s := New(runner)
	if err := s.Apply(context.Background(), config.Default()); err != nil {
		t.Fatal(err)
	}
	var disabled, stopped bool
	for _, c := range runner.commands {
		if c == "systemctl disable tuned.service" {
			disabled = true
		}
		if c == "systemctl stop tuned.service" {
			stopped = true
		}
	}
	if !disabled || !stopped {
		t.Fatalf("tuned не погашен: %v", runner.commands)
	}
}

// Гасить чужой демон надо до подсистем, которые он переопределяет: порядок
// внутри Apply — единственное, что отделяет применённое состояние от гонки.
func TestContendingDaemonsAreStoppedBeforeHostSettings(t *testing.T) {
	runner := &hostRunner{}
	s := New(runner)
	if err := s.Apply(context.Background(), config.Default()); err != nil {
		t.Fatal(err)
	}
	stop, host := -1, -1
	for i, c := range runner.commands {
		if c == "systemctl stop tuned.service" {
			stop = i
		}
		if strings.HasPrefix(c, "hostnamectl set-hostname") && host < 0 {
			host = i
		}
	}
	if stop < 0 || host < 0 || stop > host {
		t.Fatalf("чужой демон гасится не первым: %v", runner.commands)
	}
}

// Работающий чужой демон — это расхождение живой системы с конфигурацией, и
// план обязан его показать, а не промолчать.
func TestPlanReportsRunningContendingDaemon(t *testing.T) {
	runner := &hostRunner{active: true}
	s := New(runner)
	actions, err := s.Plan(nil, config.Default())
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, a := range actions {
		if strings.Contains(a.Detail, "tuned.service") {
			found = true
		}
	}
	if !found {
		t.Fatalf("план умолчал о работающем tuned: %#v", actions)
	}
}
