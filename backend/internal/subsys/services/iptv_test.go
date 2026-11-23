package services

import (
	"context"
	"fmt"
	"github.com/netos-router/netos/internal/config"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestIPTVLinkSelectionAndFreshness(t *testing.T) {
	c := iptvFixture()
	c.IPTV.Networks = []string{"other", "lan", "lan"}
	c.Interfaces = append(c.Interfaces, config.Interface{ID: "lan", Name: "duplicate"})
	c.Networks[0].Interface = "missing"
	want := []iptvLink{{"up0", ""}, {"", "10.99.0.1/24"}, {"other0", "10.98.0.1/24"}}
	if got := configuredIPTVLinks(c); !slices.Equal(got, want) {
		t.Fatalf("missing interface: %+v", got)
	}
	c.Networks[0].Interface = "lan"
	c.Interfaces[1].Name = "renamed"
	want[1].name = "renamed"
	if got := configuredIPTVLinks(c); !slices.Equal(got, want) {
		t.Fatalf("renamed first interface: %+v", got)
	}
	s := NewIPTV(&iptvRunner{active: true}, t.TempDir())
	s.VIFPath = filepath.Join(s.StateDir, "vifs")
	if err := os.WriteFile(s.VIFPath, []byte("0 up0\n1 renamed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(context.Background(), c); err == nil || !strings.Contains(err.Error(), "other0") {
		t.Fatalf("missing downstream: %v", err)
	}
	c.Networks[1].Enabled = false
	if err := s.Health(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

func iptvFixture() *config.Config {
	c := config.Default()
	c.Interfaces = []config.Interface{{ID: "up", Name: "up0", Enabled: true}, {ID: "lan", Name: "br0", Enabled: true}, {ID: "other", Name: "other0", Enabled: true}}
	c.WANs = []config.WAN{{ID: "wan", Interface: "up", Enabled: true, Proto: "static", Address: "192.0.2.1/24"}}
	c.Networks = []config.Network{{ID: "lan", Interface: "lan", Enabled: true, RouterAddress: "10.99.0.1/24"}, {ID: "other", Interface: "other", Enabled: true, RouterAddress: "10.98.0.1/24"}}
	c.IPTV = config.IPTV{Enabled: true, Upstream: "wan", Networks: []string{"lan"}}
	return c
}

type iptvRunner struct {
	active bool
	calls  []string
	fail   bool
}

type iptvReloadRunner struct {
	iptvRunner
	failReload bool
}

func (r *iptvReloadRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := r.iptvRunner.Run(ctx, name, args...)
	if r.failReload && name == "systemctl" && slices.Equal(args, []string{"daemon-reload"}) {
		return "", fmt.Errorf("reload failed")
	}
	return out, err
}

func TestIPTVRetryUnitRemoval(t *testing.T) {
	ctx := context.Background()
	c := iptvFixture()
	c.IPTV.Enabled = false
	r := &iptvReloadRunner{failReload: true}
	s := NewIPTV(r, t.TempDir())
	s.UnitDir = t.TempDir()
	conf, unit := s.paths()
	if err := os.WriteFile(unit, s.unit(), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, c); err == nil {
		t.Fatal("reload failure hidden")
	}
	if _, err := os.Stat(unit); !os.IsNotExist(err) {
		t.Fatal("unit still present", err)
	}
	// A restarted daemon must recover using only persisted state.
	next := NewIPTV(r, s.StateDir)
	next.UnitDir = s.UnitDir
	r.calls = nil
	if err := os.WriteFile(unit, []byte("foreign"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := next.Apply(ctx, c); err == nil || len(r.calls) != 0 {
		t.Fatal("accepted foreign unit", err, r.calls)
	}
	if err := os.Remove(unit); err != nil {
		t.Fatal(err)
	}
	if err := next.Apply(ctx, c); err == nil {
		t.Fatal("lost pending reload after restart")
	}
	r.failReload = false
	for i := 0; i < 2; i++ {
		if err := next.Apply(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(r.calls, []string{"systemctl daemon-reload", "systemctl daemon-reload"}) {
		t.Fatal(r.calls)
	}
	for _, path := range []string{conf, unit, filepath.Join(s.StateDir, "iptv.links")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("remaining file", path, err)
		}
	}
}

func TestIPTVEnableAfterInterruptedRemoval(t *testing.T) {
	ctx := context.Background()
	c := iptvFixture()
	r := &iptvReloadRunner{failReload: true}
	s := NewIPTV(r, t.TempDir())
	s.UnitDir = t.TempDir()
	s.links = func([]iptvLink) (string, error) { return "live links", nil }
	s.VIFPath = filepath.Join(s.StateDir, "vifs")
	if err := os.WriteFile(s.VIFPath, []byte("0 up0\n1 br0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, unit := s.paths()
	if err := os.WriteFile(unit, s.unit(), 0644); err != nil {
		t.Fatal(err)
	}
	c.IPTV.Enabled = false
	if err := s.Apply(ctx, c); err == nil {
		t.Fatal("missing reload error")
	}
	c.IPTV.Enabled = true
	r.failReload = false
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	if state, err := os.ReadFile(filepath.Join(s.StateDir, "iptv.links")); err != nil || string(state) != "live links" {
		t.Fatal("enable did not replace the removal marker", err)
	}
	r.calls = nil
	if err := s.Reconcile(ctx, c); err != nil || len(r.calls) != 0 {
		t.Fatal("stable link after recovery", err, r.calls)
	}
}

func (r *iptvRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, line)
	if strings.Contains(line, " restart ") {
		if r.fail {
			return "", fmt.Errorf("start failure")
		}
		r.active = true
	}
	if strings.Contains(line, " stop ") {
		r.active = false
	}
	if strings.Contains(line, " is-active ") {
		if r.active {
			return "active", nil
		}
		return "inactive", fmt.Errorf("inactive")
	}
	return "", nil
}
func (r *iptvRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestIPTVLifecycleAndLinkRecovery(t *testing.T) {
	c := iptvFixture()
	r := &iptvRunner{}
	s := NewIPTV(r, t.TempDir())
	s.UnitDir = t.TempDir()
	s.VIFPath = filepath.Join(t.TempDir(), "vifs")
	if err := os.WriteFile(s.VIFPath, []byte("Interface BytesIn\n0 up0 0\n1 br0 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	state := "original"
	ready := true
	s.links = func([]iptvLink) (string, error) {
		if !ready {
			return "", fmt.Errorf("no address")
		}
		return state, nil
	}
	ctx := context.Background()
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	r.calls = nil
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	for _, v := range r.calls {
		if strings.Contains(v, "restart") {
			t.Fatal("unchanged service restarted")
		}
	}
	r.calls = nil
	if err := s.Reconcile(ctx, c); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 0 {
		t.Fatal("stable link started subprocess")
	}
	ready = false
	if err := s.Reconcile(ctx, c); err == nil {
		t.Fatal("missing link hidden")
	}
	if r.active {
		t.Fatal("stale proxy remains active")
	}
	ready = true
	if err := s.Reconcile(ctx, c); err != nil {
		t.Fatal(err)
	}
	if !r.active {
		t.Fatal("same-address recovery did not restart")
	}
	state = "new-address"
	r.fail = true
	if err := s.Reconcile(ctx, c); err == nil {
		t.Fatal("failed start hidden")
	}
	r.fail = false
	if err := s.Reconcile(ctx, c); err != nil {
		t.Fatal("retry", err)
	}
	c.IPTV.Enabled = false
	if err := (&IPTVPreparation{s}).Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	if r.active {
		t.Fatal("preparation did not stop")
	}
	if err := s.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	conf, unit := s.paths()
	for _, p := range []string{conf, unit, filepath.Join(s.StateDir, "iptv.links")} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatal("left owned file", p)
		}
	}
}

func TestIPTVRenderOwnershipAndPlan(t *testing.T) {
	c := iptvFixture()
	data := string(RenderIPTV(c))
	for _, v := range []string{"phyint up0 upstream", "phyint br0 downstream", "altnet 0.0.0.0/0"} {
		if !strings.Contains(data, v) {
			t.Fatal("missing", v)
		}
	}
	if strings.Contains(data, "quickleave") || strings.Contains(data, "other0") {
		t.Fatal("unsafe scope", data)
	}
	r := &iptvRunner{}
	s := NewIPTV(r, t.TempDir())
	s.UnitDir = t.TempDir()
	conf, unit := s.paths()
	if err := os.WriteFile(unit, []byte("foreign"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(context.Background(), c); err == nil {
		t.Fatal("overwrote foreign unit")
	}
	_ = os.WriteFile(unit, s.unit(), 0644)
	_ = os.WriteFile(conf, RenderIPTV(c), 0644)
	next := *c
	next.WANs = append([]config.WAN(nil), c.WANs...)
	next.WANs[0].Name = "Renamed"
	if actions, err := s.Plan(c, &next); err != nil || len(actions) != 0 {
		t.Fatal("label planned restart", actions, err)
	}
	next.IPTV.Networks = []string{"other"}
	if actions, err := s.Plan(c, &next); err != nil || len(actions) != 1 {
		t.Fatal("scope absent from plan", actions, err)
	}
}
