package components

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type batchRunner struct {
	versions          map[string]string
	installs          []string
	queries, policies int
	fail              bool
}

func (r *batchRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	switch name {
	case "dpkg-query":
		r.queries++
		var lines []string
		for p, v := range r.versions {
			lines = append(lines, p+"\tii \t"+v)
		}
		return strings.Join(lines, "\n"), nil
	case "apt-cache":
		r.policies++
		return "shared:\n  Candidate: 2\nsecond:\n  Candidate: 2\n", nil
	case "dpkg":
		return "", nil
	case "apt-get":
		for _, arg := range args {
			if p, v, ok := strings.Cut(arg, "="); ok && (p == "shared" || p == "second") {
				r.installs = append(r.installs, arg)
				if r.fail {
					return "", fmt.Errorf("test install failure")
				}
				r.versions[p] = v
			}
		}
		return "", nil
	}
	return "", fmt.Errorf("unexpected %s %v", name, args)
}
func (r *batchRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func batchManager(t *testing.T) (*UpdateManager, *batchRunner, []UpdateRequest) {
	t.Helper()
	oldCatalog, oldPolicy := config.Catalog, system.PolicyRCPath
	t.Cleanup(func() { config.Catalog = oldCatalog; system.PolicyRCPath = oldPolicy })
	config.Catalog = []config.ComponentInfo{{ID: "first", Packages: []string{"shared"}}, {ID: "second", Packages: []string{"shared", "second"}}}
	system.PolicyRCPath = filepath.Join(t.TempDir(), "policy-rc.d")
	r := &batchRunner{versions: map[string]string{"shared": "1", "second": "1"}}
	s := New(r, testLogger{})
	s.Packages.OwnershipDir = ""
	rows, err := s.checkUpdates(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	m := NewUpdateManager(s, filepath.Join(t.TempDir(), "updates.json"))
	m.state.Components = rows
	r.queries, r.policies = 0, 0
	return m, r, []UpdateRequest{{ID: "first", Token: rows["first"].Token}, {ID: "second", Token: rows["second"].Token}}
}
func waitBatch(t *testing.T, m *UpdateManager) UpdateSnapshot {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for m.Snapshot().Operation.Active && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	got := m.Snapshot()
	if got.Operation.Active {
		t.Fatal("batch did not finish")
	}
	return got
}
func TestBatchSharedPackagesAndSnapshot(t *testing.T) {
	m, r, requests := batchManager(t)
	started, release := make(chan struct{}), make(chan struct{})
	m.Run = func(_ context.Context, fn func() error) error { close(started); <-release; return fn() }
	if err := m.StartUpdates(context.Background(), requests); err != nil {
		t.Fatal(err)
	}
	<-started
	queued := m.Snapshot()
	if queued.Operations["first"].Status != "queued" || queued.Operations["second"].Status != "queued" {
		t.Fatal(queued)
	}
	if err := m.Start(context.Background(), "", ""); err == nil {
		t.Fatal("parallel check accepted")
	}
	close(release)
	got := waitBatch(t, m)
	if got.Error != "" || got.Operations["first"].Status != "succeeded" || got.Operations["second"].Status != "succeeded" {
		t.Fatal(got)
	}
	if strings.Join(r.installs, ",") != "shared=2,second=2" {
		t.Fatal("shared package installed twice", r.installs)
	}
	if r.queries != 2 || r.policies != 2 {
		t.Fatalf("checks must be batched before/after, got %d/%d", r.queries, r.policies)
	}
	if queued.Operations["first"].Status != "queued" {
		t.Fatal("published map changed")
	}
	for _, row := range got.Components {
		if row.UpdateAvailable {
			t.Fatal("stale update after success")
		}
	}
}
func TestBatchRejectsStaleBeforeAnyInstallation(t *testing.T) {
	m, r, requests := batchManager(t)
	requests[1].Token = "stale"
	if err := m.StartUpdates(context.Background(), requests); err != nil {
		t.Fatal(err)
	}
	got := waitBatch(t, m)
	if got.Error == "" || len(r.installs) != 0 {
		t.Fatal(got, r.installs)
	}
	for _, op := range got.Operations {
		if op.Status != "cancelled" {
			t.Fatal(op)
		}
	}
}
func TestSingleUpdateUsesSameQueue(t *testing.T) {
	m, r, requests := batchManager(t)
	if err := m.Start(context.Background(), requests[0].ID, requests[0].Token); err != nil {
		t.Fatal(err)
	}
	got := waitBatch(t, m)
	if got.Error != "" || len(got.Operations) != 1 || got.Operations["first"].Status != "succeeded" {
		t.Fatal(got)
	}
	if strings.Join(r.installs, ",") != "shared=2" || !got.Components["second"].UpdateAvailable {
		t.Fatal("unselected component changed", r.installs, got.Components)
	}
}
func TestBatchFailureStopsQueueAndAllowsRetry(t *testing.T) {
	m, r, requests := batchManager(t)
	r.fail = true
	if err := m.StartUpdates(context.Background(), requests); err != nil {
		t.Fatal(err)
	}
	got := waitBatch(t, m)
	if got.Operations["first"].Status != "failed" || got.Operations["second"].Status != "cancelled" || len(r.installs) != 1 {
		t.Fatal(got, r.installs)
	}
	r.fail = false
	if err := m.StartUpdates(context.Background(), requests); err != nil {
		t.Fatal(err)
	}
	if got = waitBatch(t, m); got.Error != "" {
		t.Fatal(got)
	}
}
func TestBatchRejectedMaintenanceAndInvalidSelection(t *testing.T) {
	m, r, requests := batchManager(t)
	for _, bad := range [][]UpdateRequest{nil, {{ID: "absent", Token: "x"}}, {requests[0], requests[0]}} {
		if err := m.StartUpdates(context.Background(), bad); err == nil {
			t.Fatal("bad selection accepted")
		}
	}
	m.Run = func(context.Context, func() error) error { return fmt.Errorf("apply pending") }
	if err := m.StartUpdates(context.Background(), requests); err != nil {
		t.Fatal(err)
	}
	got := waitBatch(t, m)
	if got.Error == "" || len(r.installs) != 0 {
		t.Fatal(got)
	}
	for _, op := range got.Operations {
		if op.Status != "cancelled" {
			t.Fatal(op)
		}
	}
}
func TestUpdateProgressKeepsOwnerDuringValidation(t *testing.T) {
	p := &Progress{}
	p.Start("update", "ocserv")
	p.Stage("", "Check versions")
	if p.Snapshot().Component != "ocserv" {
		t.Fatal("lost component")
	}
	p.Start("check", "")
	p.Stage("xray", "Check release")
	if p.Snapshot().Component != "xray" {
		t.Fatal("check failed to select component")
	}
}
func TestRejectedQueueDoesNotOverwriteApplyProgress(t *testing.T) {
	m, r, requests := batchManager(t)
	m.Subsystem.Progress.Start("install", "dnsmasq")
	m.Subsystem.Progress.Stage("dnsmasq", "Installing")
	before := m.Subsystem.Progress.Snapshot()
	m.Run = func(context.Context, func() error) error { return fmt.Errorf("apply busy") }
	if err := m.StartUpdates(context.Background(), requests); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		m.mu.Lock()
		busy := m.busy
		m.mu.Unlock()
		if !busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("queue stayed busy")
		}
		time.Sleep(time.Millisecond)
	}
	if got := m.Subsystem.Progress.Snapshot(); got != before {
		t.Fatal("apply progress overwritten", got)
	}
	if len(r.installs) != 0 {
		t.Fatal(r.installs)
	}
}
func TestCancelledQueueDoesNotInstall(t *testing.T) {
	m, r, requests := batchManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.StartUpdates(ctx, requests); err != nil {
		t.Fatal(err)
	}
	got := waitBatch(t, m)
	if got.Error == "" || len(r.installs) > 0 {
		t.Fatal(got, r.installs)
	}
}
func BenchmarkBatchSnapshot(b *testing.B) {
	for _, count := range []int{10, 100, 1000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			m := NewUpdateManager(New(&updateTestRunner{}, testLogger{}), filepath.Join(b.TempDir(), "state"))
			m.operations = map[string]Operation{}
			for i := 0; i < count; i++ {
				id := fmt.Sprint(i)
				m.operations[id] = Operation{Component: id, Status: "queued"}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = m.Snapshot()
			}
		})
	}
}
