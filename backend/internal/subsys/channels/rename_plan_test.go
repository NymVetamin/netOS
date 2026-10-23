package channels

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/netos-router/netos/internal/apply"
)

func TestWireGuardRenameConfirmation(t *testing.T) {
	s, _ := newTestSubsystem(t)
	old := channelConfig()
	if err := s.Apply(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	next := channelConfig()
	next.Channels[len(next.Channels)-1].Name = "Renamed"
	check := func(want bool) {
		t.Helper()
		actions, err := s.Plan(old, next)
		if err != nil || apply.NeedsConfirmation(actions) != want {
			t.Fatalf("confirmation want=%v actions=%+v err=%v", want, actions, err)
		}
	}
	check(false)
	next.Channels[len(next.Channels)-1].FailMode = "direct"
	check(true)
	next.Channels[len(next.Channels)-1].FailMode = "block"
	if err := os.WriteFile(filepath.Join(s.StateDir, "wg-ch1.conf"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	check(true)
	if old.Channels[len(old.Channels)-1].Name == "Renamed" {
		t.Fatal("comparison mutated old revision")
	}
}
