package samba

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

func TestDiscoveryRecoveryOnlyRestartsDiscoveryAndRetriesFailure(t *testing.T) {
	r := newRunner()
	m := NewDiscoveryMonitor(r)
	cfg := fixture()
	r.fail = "restart"
	if err := m.recover(context.Background(), cfg); err == nil {
		t.Fatal("restart failure was hidden")
	}
	r.fail = ""
	if err := m.recover(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	want := []string{"systemctl restart netos-wsdd.service", "systemctl restart netos-wsdd.service"}
	if !reflect.DeepEqual(r.calls, want) {
		t.Fatalf("unexpected commands (Samba must not restart): %v", r.calls)
	}
}

func TestDiscoveryRecoveryDisabledDoesNotStartServices(t *testing.T) {
	for _, mode := range []string{"nil", "samba-disabled", "discovery-disabled", "no-lan", "disabled-lan", "unknown-lan"} {
		t.Run(mode, func(t *testing.T) {
			cfg := fixture()
			switch mode {
			case "nil":
				cfg = nil
			case "samba-disabled":
				cfg.Samba.Enabled = false
			case "discovery-disabled":
				cfg.Samba.Discovery = false
			case "no-lan":
				cfg.Samba.Networks = nil
			case "disabled-lan":
				cfg.Networks[0].Enabled = false
			case "unknown-lan":
				cfg.Samba.Networks = []string{"missing"}
			}
			r := newRunner()
			if err := NewDiscoveryMonitor(r).recover(context.Background(), cfg); err != nil || len(r.calls) != 0 {
				t.Fatalf("disabled discovery caused service operations: %v, %v", r.calls, err)
			}
		})
	}
}

func TestDiscoveryEventsBatchIdleRetryAndResubscribe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewDiscoveryMonitor(newRunner())
	first, second := make(chan error, 64), make(chan error, 64)
	var subscriptions atomic.Int32
	m.subscribe = func(context.Context) (<-chan error, error) {
		switch subscriptions.Add(1) {
		case 1:
			return nil, errors.New("open failed")
		case 2:
			return first, nil
		default:
			return second, nil
		}
	}
	var calls atomic.Int32
	var fail atomic.Bool
	fail.Store(true)
	called := make(chan struct{}, 64)
	maintain := func(context.Context, func(*config.Config) error) error {
		calls.Add(1)
		called <- struct{}{}
		if fail.Swap(false) {
			return errors.New("signal failed")
		}
		return nil
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.runEvents(ctx, maintain, func(string, ...any) {}, 30*time.Millisecond, 20*time.Millisecond)
	}()
	wait := func() {
		t.Helper()
		select {
		case <-called:
		case <-time.After(time.Second):
			t.Fatal("reconcile did not run")
		}
	}
	wait() // Open failure retried, then reconciliation fails.
	wait() // Failed operation retried without a new network event.
	stable := calls.Load()
	time.Sleep(90 * time.Millisecond)
	if calls.Load() != stable {
		t.Fatal("polling while idle")
	}
	for i := 0; i < 40; i++ {
		first <- nil
	}
	wait()
	time.Sleep(70 * time.Millisecond)
	if calls.Load() != stable+1 {
		t.Fatalf("burst not coalesced: %d", calls.Load())
	}
	first <- errors.New("ENOBUFS")
	close(first)
	wait()
	if subscriptions.Load() != 3 {
		t.Fatalf("subscriptions=%d", subscriptions.Load())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel did not stop event loop")
	}
}
