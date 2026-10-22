//go:build linux

package channels

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type failingRouteReader struct{ *system.Exec }

func (r failingRouteReader) ChannelRouteState(context.Context, int, string) (bool, bool, error) {
	return false, false, errors.New("injected interrupted dump")
}

func TestChannelRouteRepairKernel(t *testing.T) {
	if os.Getenv("NETOS_TEST_NETWORK_NAMESPACE") != "1" {
		t.Skip("requires isolated network namespace")
	}
	ctx := context.Background()
	ch := config.Channel{Index: 234, Type: "xray"}
	name := InterfaceName(ch)
	ip := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %s %v", args, out, err)
		}
		return string(out)
	}
	ip("link", "add", name, "type", "dummy")
	defer exec.Command("ip", "link", "del", name).Run()
	ip("link", "set", name, "up")
	e := system.NewExec()
	var commands []string
	e.OnCommand = func(n string, a []string) { commands = append(commands, n+" "+strings.Join(a, " ")) }
	s := New(e, t.TempDir())
	check := func() {
		t.Helper()
		out := ip("-4", "route", "show", "table", "1234")
		if !hasDefaultRoute(out, name) || !hasBlackholeDefault(out) {
			t.Fatal(out)
		}
	}
	if err := s.ensureRoutes(ctx, ch, name); err != nil {
		t.Fatal(err)
	}
	check()
	commands = nil
	for i := 0; i < 10; i++ {
		if err := s.ensureRoutes(ctx, ch, name); err != nil {
			t.Fatal(err)
		}
	}
	if len(commands) != 0 {
		t.Fatalf("unchanged routes spawned commands: %v", commands)
	}
	ip("route", "del", "default", "dev", name, "table", "1234", "metric", "100")
	if err := s.ensureRoutes(ctx, ch, name); err != nil {
		t.Fatal(err)
	}
	check()
	ip("link", "del", name)
	ip("link", "add", name, "type", "dummy")
	ip("link", "set", name, "up")
	if err := s.ensureRoutes(ctx, ch, name); err != nil {
		t.Fatal(err)
	}
	check()
	s.Runner = failingRouteReader{e}
	commands = nil
	if err := s.ensureRoutes(ctx, ch, name); err != nil {
		t.Fatal(err)
	}
	check()
	if len(commands) != 1 || commands[0] != "ip -4 route show table 1234" {
		t.Fatalf("fallback: %v", commands)
	}
}
