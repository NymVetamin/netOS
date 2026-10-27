//go:build linux

package channels

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestFallbackResolverKernel(t *testing.T) {
	if os.Getenv("NETOS_TEST_NETWORK_NAMESPACE") != "1" {
		t.Skip("requires isolated network namespace")
	}
	ip := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %s %v", args, out, err)
		}
		return string(out)
	}
	ctx := context.Background()
	s := New(system.NewExec(), t.TempDir())
	cfg := config.Default()
	cfg.Channels = nil
	for i := 0; i < 3; i++ {
		ch := config.Channel{ID: fmt.Sprint(i), Index: 234 + i, Enabled: true, Type: "xray", FailMode: "fallback", Fallback: fmt.Sprint(i + 1)}
		cfg.Channels = append(cfg.Channels, ch)
		s.states[ch.ID] = &channelState{Down: true}
		name := InterfaceName(ch)
		ip("link", "add", name, "type", "dummy")
		t.Cleanup(func() {
			exec.Command("ip", "link", "del", name).Run()
			exec.Command("ip", "route", "flush", "table", fmt.Sprint(TableNumber(ch))).Run()
			exec.Command("ip", "rule", "del", "priority", fmt.Sprint(Priority(ch))).Run()
		})
		ip("link", "set", name, "up")
		if err := s.ensureRoutes(ctx, ch, name); err != nil {
			t.Fatal(err)
		}
	}
	cfg.Channels[2].FailMode = "direct"
	ip("link", "add", "qa-direct", "type", "dummy")
	t.Cleanup(func() { exec.Command("ip", "link", "del", "qa-direct").Run() })
	ip("link", "set", "qa-direct", "up")
	ip("route", "add", "default", "dev", "qa-direct")
	check := func(want string) {
		t.Helper()
		for repeat := 0; repeat < 2; repeat++ {
			r := newFallbackResolver(cfg, s.states)
			for _, ch := range cfg.Channels {
				if ch.Enabled && s.states[ch.ID].Down {
					if err := s.applyFallback(ctx, ch, r.resolve(ch)); err != nil {
						t.Fatal(err)
					}
				}
			}
			out, err := exec.Command("ip", "-4", "route", "get", "198.51.100.1", "mark", fmt.Sprintf("0x%x", Mark(cfg.Channels[0]))).CombinedOutput()
			if want == "" {
				if err == nil {
					t.Fatalf("blocked route usable: %s", out)
				}
			} else if err != nil || !strings.Contains(string(out), "dev "+want+" ") {
				t.Fatalf("route=%s err=%v want=%s", out, err, want)
			}
		}
	}
	check("qa-direct")
	s.states["2"].Down = false
	check(InterfaceName(cfg.Channels[2]))
	s.states["1"].Down = false
	check(InterfaceName(cfg.Channels[1]))
	cfg.Channels[1].Enabled = false
	check("")
	cfg.Channels[1].Enabled = true
	s.states["1"].Down = true
	s.states["2"].Down = true
	cfg.Channels[2].FailMode = "fallback"
	cfg.Channels[2].Fallback = "0"
	check("")
	cfg.Channels[2].FailMode = "direct"
	check("qa-direct")
}
