//go:build linux

package services

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestKeaNetlinkRealEventsAndCancellation(t *testing.T) {
	if os.Getenv("NETOS_TEST_KEA_NETLINK") != "1" {
		t.Skip("requires isolated Linux networking")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, err := subscribeKeaLinks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	wait := func() {
		t.Helper()
		select {
		case err, ok := <-events:
			if !ok || err != nil {
				t.Fatalf("subscription ended: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no kernel event")
		}
	}
	drain := func() {
		for {
			select {
			case <-events:
			case <-time.After(30 * time.Millisecond):
				return
			}
		}
	}
	// Do not delete or alter any pre-existing interface.
	if exec.Command("ip", "link", "show", "qa-kea-event").Run() == nil {
		t.Fatal("test interface already exists")
	}
	run("link", "add", "qa-kea-event", "type", "dummy")
	defer exec.Command("ip", "link", "del", "qa-kea-event").Run()
	wait()
	drain()
	run("link", "set", "qa-kea-event", "up")
	wait()
	drain()
	run("addr", "add", "192.0.2.254/32", "dev", "qa-kea-event")
	wait()
	drain()
	run("addr", "del", "192.0.2.254/32", "dev", "qa-kea-event")
	wait()
	drain()
	cancel()
	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("unexpected event after drain and cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked receive did not stop")
	}
}
