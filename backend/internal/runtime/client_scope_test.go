package runtime

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

type scopeCountersRunner struct {
	fail  bool
	bytes int
	calls int
}

func (r *scopeCountersRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	r.calls++
	if name == "ip" {
		return "[]", nil
	}
	if r.fail {
		return "", errors.New("counter read failed")
	}
	return fmt.Sprintf(`{"nftables":[{"set":{"name":"up4","elem":[{"elem":{"val":"192.0.2.2","counter":{"bytes":%d}}},{"elem":{"val":"203.0.113.9","counter":{"bytes":%d}}}]}}]}`, r.bytes, r.bytes), nil
}
func (r *scopeCountersRunner) RunInput(context.Context, string, string, ...string) (string, error) {
	panic("unexpected mutation")
}

func TestClientSampleRejectsStaleExitCounters(t *testing.T) {
	c := &config.Config{Interfaces: []config.Interface{{ID: "lan", Name: "lan0", Enabled: true}}, Networks: []config.Network{{Interface: "lan", Enabled: true, RouterAddress: "192.0.2.1/24"}}}
	c.TrafficMonitor.Enabled = true
	r := &scopeCountersRunner{bytes: 100}
	dir := t.TempDir()
	h, e := NewClientHistory(filepath.Join(dir, "history.db"), r, NewCollector(r, filepath.Join(dir, "absent-leases")), func() *config.Config { return c })
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	h.dnsCancel = func() {} // This test exercises sampling, not the journal watcher.
	h.sample(context.Background())
	if len(h.baseline) != 1 {
		t.Fatalf("stale exit counter accepted: %+v", h.baseline)
	}
	for k, v := range h.baseline {
		v.At = v.At.Add(-30 * time.Second)
		h.baseline[k] = v
	}
	h.lastPersist = time.Time{}
	r.bytes = 200
	h.sample(context.Background())
	report, e := h.Report(context.Background(), time.Now().Add(-time.Minute), time.Now().Add(time.Second), nil, false)
	if e != nil || len(report.Clients) != 1 || report.Clients[0].Address != "192.0.2.2" || report.Clients[0].TX != 100 {
		t.Fatalf("wrong accounting: %+v %v", report, e)
	}
	r.fail = true
	h.sample(context.Background())
	if h.problem == "" {
		t.Fatal("counter error hidden")
	}
	r.fail = false
	c.Networks[0].RouterAddress = "203.0.113.1/24"
	h.lastPersist = time.Time{}
	h.sample(context.Background())
	if h.problem != "" || len(h.baseline) != 1 {
		t.Fatal("recovery failed", h.problem, h.baseline)
	}
	for _, v := range h.baseline {
		if v.Address != "203.0.113.9" {
			t.Fatal("old scope retained", v)
		}
	}
	if r.calls != 8 {
		t.Fatal("unexpected commands", r.calls)
	}
}
