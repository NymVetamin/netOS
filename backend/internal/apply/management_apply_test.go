package apply

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type managementApplySubsystem struct {
	testSubsystem
	mixed bool
}

func (s *managementApplySubsystem) PlanContext(ctx context.Context, _, _ *config.Config) ([]Action, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	remote, local := ManagementConnection(ctx)
	classification := ConfirmationRequired
	if remote == netip.MustParseAddr("192.0.2.2") && local == netip.MustParseAddr("192.0.2.1") {
		classification = ConfirmationSafe
	}
	actions := []Action{{Kind: "update", Confirmation: classification}}
	if s.mixed {
		actions = append(actions, Action{Kind: "update", Disruptive: true})
	}
	return actions, nil
}

func TestApplyPreservesManagementContextWhenReplanning(t *testing.T) {
	for _, mode := range []string{"LAN", "unknown", "mixed", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			s := &managementApplySubsystem{mixed: mode == "mixed"}
			e := NewEngine(testLogger{}, false)
			if err := e.Register(s); err != nil {
				t.Fatal(err)
			}
			if _, err := e.Apply(context.Background(), validConfig("before"), 1, false); err != nil {
				t.Fatal(err)
			}
			defer e.Rollback(context.Background())
			ctx := context.Background()
			if mode != "unknown" {
				ctx = WithManagementConnection(ctx, netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"))
			}
			if mode == "canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			result, err := e.Apply(ctx, validConfig("after"), 2, true)
			if mode == "canceled" {
				if !errors.Is(err, context.Canceled) || e.Current().System.Hostname != "before" {
					t.Fatalf("canceled plan: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := mode != "LAN"
			pending, _ := e.Pending()
			if result.NeedsConfirm != want || pending != want {
				t.Fatalf("confirmation=%v pending=%v want=%v", result.NeedsConfirm, pending, want)
			}
		})
	}
}
