package apply

import (
	"context"
	"errors"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestExplicitConfirmationClassification(t *testing.T) {
	safe := Action{Subsystem: "firewall", Confirmation: ConfirmationSafe}
	for _, tc := range []struct {
		name    string
		actions []Action
		want    bool
	}{
		{"safe", []Action{safe}, false},
		{"legacy risk", []Action{{Subsystem: "firewall"}}, true},
		{"legacy exempt", []Action{{Subsystem: "dns"}}, false},
		{"required", []Action{{Subsystem: "dns", Confirmation: ConfirmationRequired}}, true},
		{"unknown", []Action{{Subsystem: "dns", Confirmation: "future-value"}}, true},
		{"disruptive wins", []Action{{Subsystem: "firewall", Confirmation: ConfirmationSafe, Disruptive: true}}, true},
		{"mixed", []Action{safe, {Subsystem: "routing"}}, true},
		{"mixed reverse", []Action{{Subsystem: "routing"}, safe}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NeedsConfirmation(tc.actions); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

type classifiedSubsystem struct {
	failApply, failHealth bool
	applied               string
}

func (s *classifiedSubsystem) Name() string { return "firewall" }
func (s *classifiedSubsystem) Plan(*config.Config, *config.Config) ([]Action, error) {
	return []Action{{Kind: "update", Confirmation: ConfirmationSafe}}, nil
}
func (s *classifiedSubsystem) Apply(_ context.Context, c *config.Config) error {
	s.applied = c.System.Hostname
	if s.failApply && s.applied == "next" {
		return errors.New("apply failure")
	}
	return nil
}
func (s *classifiedSubsystem) Health(_ context.Context, c *config.Config) error {
	if s.failHealth && c.System.Hostname == "next" {
		return errors.New("health failure")
	}
	return nil
}
func TestSafeActionStillValidatesAndRollsBack(t *testing.T) {
	for _, mode := range []string{"success", "apply failure", "health failure", "validation"} {
		t.Run(mode, func(t *testing.T) {
			s := &classifiedSubsystem{failApply: mode == "apply failure", failHealth: mode == "health failure"}
			e := NewEngine(testLogger{}, false)
			if err := e.Register(s); err != nil {
				t.Fatal(err)
			}
			if _, err := e.Apply(context.Background(), validConfig("initial"), 1, false); err != nil {
				t.Fatal(err)
			}
			next := validConfig("next")
			if mode == "validation" {
				next.System.Hostname = "invalid name"
			}
			res, err := e.Apply(context.Background(), next, 2, true)
			if mode == "success" {
				if err != nil || res.NeedsConfirm || s.applied != "next" {
					t.Fatalf("result=%+v error=%v applied=%s", res, err, s.applied)
				}
			} else if err == nil || s.applied != "initial" {
				t.Fatalf("error=%v applied=%s", err, s.applied)
			}
			if pending, _ := e.Pending(); pending {
				t.Fatal("unexpected pending confirmation")
			}
		})
	}
}
