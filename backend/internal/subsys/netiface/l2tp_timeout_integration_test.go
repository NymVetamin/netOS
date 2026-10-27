//go:build linux

package netiface

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func TestIntegrationL2TPGatewayDeadlineAndRetry(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("NETOS_INTEGRATION=1 and root required")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	init, initErr := os.Readlink("/proc/1/ns/net")
	if err != nil || initErr != nil || self == init {
		t.Fatal("isolated network namespace required")
	}
	r := system.NewExec()
	run := func(args ...string) {
		t.Helper()
		if out, err := r.Run(context.Background(), "ip", args...); err != nil {
			t.Fatalf("ip %v: %s %v", args, out, err)
		}
	}
	const iface = "qa-lns-wait"
	run("link", "add", iface, "type", "dummy")
	t.Cleanup(func() { _, _ = r.Run(context.Background(), "ip", "link", "del", iface) })
	run("link", "set", iface, "up")
	run("addr", "add", "192.0.2.1/24", "dev", iface)
	run("route", "add", "default", "via", "192.0.2.253", "dev", iface, "proto", "static", "metric", "100")
	s := &WAN{Runner: r, DHCPTimeout: 40 * time.Millisecond, DHCPPoll: 5 * time.Millisecond}
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		start := time.Now()
		gateway, err := s.waitUnderlayGateway(ctx, iface)
		elapsed := time.Since(start)
		cancel()
		t.Logf("attempt %d: own timeout 40ms, elapsed %s, error %v", attempt, elapsed, err)
		if err != nil || gateway != "" || elapsed < s.DHCPTimeout || elapsed > 500*time.Millisecond {
			t.Fatalf("timeout did not bound waiting: gateway=%q elapsed=%s err=%v", gateway, elapsed, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	err = s.routeToLNS(ctx, config.WAN{Name: "QA", Server: "198.51.100.1", Underlay: "dhcp"}, iface, nil)
	cancel()
	if err == nil || !strings.Contains(err.Error(), "не найден шлюз сети провайдера") {
		t.Fatalf("missing provider gateway did not reach caller: %v", err)
	}
	s.DHCPTimeout = time.Second
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	start := time.Now()
	_, err = s.waitUnderlayGateway(ctx, iface)
	// Cancellation can interrupt either the timer or the real ip process.
	// The latter retains the runner's wrapped command error.
	cancelled := ctx.Err() == context.DeadlineExceeded
	cancel()
	if !cancelled || err == nil || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("outer cancellation lost: %v", err)
	}
	added := make(chan error, 1)
	go func() {
		time.Sleep(30 * time.Millisecond)
		_, err := r.Run(context.Background(), "ip", "route", "add", "default", "via", "192.0.2.254", "dev", iface, "proto", "dhcp", "metric", "200")
		added <- err
	}()
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	gateway, err := s.waitUnderlayGateway(ctx, iface)
	cancel()
	if addErr := <-added; addErr != nil {
		t.Fatal(addErr)
	}
	if err != nil || gateway != "192.0.2.254" {
		t.Fatalf("late DHCP gateway/retry: %q %v", gateway, err)
	}
	if gateway, err := s.waitUnderlayGateway(context.Background(), iface); err != nil || gateway != "192.0.2.254" {
		t.Fatalf("existing DHCP gateway: %q %v", gateway, err)
	}
}
