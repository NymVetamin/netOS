package netconf

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

type backendUnitRunner struct {
	present  map[string]bool
	active   map[string]bool
	enabled  map[string]bool
	masked   map[string]bool
	commands []string
}

func (r *backendUnitRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	if name != "systemctl" || len(args) < 1 {
		return "", nil
	}
	unit := ""
	if len(args) > 1 {
		unit = args[len(args)-1]
	}
	switch args[0] {
	case "list-unit-files":
		if r.present[unit] {
			return unit + " enabled\n", nil
		}
		return "", nil
	case "is-active":
		if r.active[unit] {
			return "active\n", nil
		}
		return "inactive\n", fmt.Errorf("inactive")
	case "is-enabled":
		if r.masked[unit] {
			return "masked\n", fmt.Errorf("masked")
		}
		if r.enabled[unit] {
			return "enabled\n", nil
		}
		return "disabled\n", fmt.Errorf("disabled")
	case "enable":
		r.enabled[unit] = true
	case "start":
		r.active[unit] = true
	case "disable":
		r.enabled[unit] = false
	case "mask":
		r.masked[unit] = true
		r.enabled[unit] = false
	case "unmask":
		r.masked[unit] = false
	case "stop":
		r.active[unit] = false
	}
	return "", nil
}

func (r *backendUnitRunner) RunInput(context.Context, string, string, ...string) (string, error) {
	return "", nil
}

func newBackendUnitRunner() *backendUnitRunner {
	return &backendUnitRunner{
		present: map[string]bool{"networking.service": true, "systemd-networkd.service": true, "systemd-networkd.socket": true},
		active:  map[string]bool{}, enabled: map[string]bool{}, masked: map[string]bool{},
	}
}

func TestActivateIfupdownStopsAndDisablesNetworkd(t *testing.T) {
	r := newBackendUnitRunner()
	r.active["systemd-networkd.service"] = true
	r.enabled["systemd-networkd.service"] = true
	r.active["systemd-networkd.socket"] = true
	r.enabled["systemd-networkd.socket"] = true
	s := New(r, nil)
	if err := s.activateBackend(context.Background(), "ifupdown"); err != nil {
		t.Fatal(err)
	}
	if !r.active["networking.service"] || !r.enabled["networking.service"] ||
		r.active["systemd-networkd.service"] || r.enabled["systemd-networkd.service"] ||
		r.active["systemd-networkd.socket"] || r.enabled["systemd-networkd.socket"] {
		t.Fatalf("wrong unit state: active=%v enabled=%v", r.active, r.enabled)
	}
}

func TestActivateNetworkdStopsAndDisablesIfupdown(t *testing.T) {
	r := newBackendUnitRunner()
	r.active["networking.service"] = true
	r.enabled["networking.service"] = true
	s := New(r, nil)
	if err := s.activateBackend(context.Background(), "networkd"); err != nil {
		t.Fatal(err)
	}
	if !r.active["systemd-networkd.service"] || !r.enabled["systemd-networkd.service"] ||
		r.active["networking.service"] || r.enabled["networking.service"] {
		t.Fatalf("wrong unit state: active=%v enabled=%v", r.active, r.enabled)
	}
}

func TestBackendServiceDriftIsVisibleInPlanAndHealth(t *testing.T) {
	r := newBackendUnitRunner()
	r.active["systemd-networkd.service"] = true
	r.enabled["systemd-networkd.service"] = true
	cfg := routerConfig()
	cfg.System.NetworkBackend = "ifupdown"
	s := New(r, nil)
	actions, err := s.Plan(cfg, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) == 0 {
		t.Fatal("service ownership drift is absent from plan")
	}
	if err := s.Health(context.Background(), cfg); err == nil {
		t.Fatal("service ownership drift passed health check")
	}
}
