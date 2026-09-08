package channels

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReportMonitorRepairsRouteWithoutProbe(t *testing.T) {
	s, r := newTestSubsystem(t)
	cfg := channelConfig()
	if err := s.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Channels[1].Probe.Enabled = false
	s.pausedUntil = time.Time{}
	r.routes = "blackhole default proto netos metric 1000\n"
	s.tick(context.Background(), cfg)
	if !strings.Contains(r.routes, "default dev wg-ch1") {
		t.Fatal("recreated interface keeps only blackhole")
	}
}

type reportXrayRunner struct{ *channelRunner }

func (r *reportXrayRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	if strings.Contains(command, "route replace default dev tun-ch1") {
		r.commands = append(r.commands, command)
		r.routes += "default dev tun-ch1 proto netos metric 100\n"
		return "", nil
	}
	return r.channelRunner.Run(ctx, name, args...)
}

func TestReportXrayRestartRepairsOwnTableDuringFallback(t *testing.T) {
	s, r := newTestSubsystem(t)
	cfg := channelConfig()
	ch := &cfg.Channels[1]
	ch.Type = "xray"
	ch.Probe.Enabled = true
	ch.FailMode = "fallback"
	ch.Fallback = "reserve"
	reserve := *ch
	reserve.ID, reserve.Index = "reserve", 2
	reserve.Probe.Enabled = false
	reserve.FailMode, reserve.Fallback = "block", ""
	cfg.Channels = append(cfg.Channels, reserve)
	if err := os.MkdirAll(filepath.Join(s.SysClassNet, "tun-ch1"), 0755); err != nil {
		t.Fatal(err)
	}
	s.Runner = &reportXrayRunner{r}
	r.routes = "blackhole default proto netos metric 1000\n"
	r.rules = "10001: from all fwmark 0x1001 lookup 1002\n"
	s.states[ch.ID] = &channelState{Down: true, Next: time.Now().Add(time.Hour)}
	s.tick(context.Background(), cfg)
	if !strings.Contains(r.routes, "default dev tun-ch1") {
		t.Fatal("Xray table remains blackholed after TUN recovery")
	}
	if !strings.Contains(r.rules, "lookup 1002") {
		t.Fatal("route repair prematurely removed fallback")
	}
	r.commands = nil
	s.tick(context.Background(), cfg)
	for _, command := range r.commands {
		if strings.Contains(command, "route replace") {
			t.Fatalf("healthy route rewritten: %s", command)
		}
	}
}
