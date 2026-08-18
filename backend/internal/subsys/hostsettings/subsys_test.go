package hostsettings

import (
	"context"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type hostRunner struct{ commands []string }

func (r *hostRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	switch command {
	case "hostnamectl --static":
		return "router\n", nil
	case "timedatectl show --property=Timezone --value":
		return "Europe/Moscow\n", nil
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
