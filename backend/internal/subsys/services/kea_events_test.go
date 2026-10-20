package services

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

func TestKeaEventsBatchIdleRetryAndResubscribe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewKeaLinkMonitor(&serviceRunner{})
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
