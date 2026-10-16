package runtime

import (
	"context"
	"github.com/netos-router/netos/internal/config"
	"path/filepath"
	"testing"
	"time"
)

func TestLiveLeaseAndAccountingIndependentFromHistory(t *testing.T) {
	cfg := config.Default()
	cfg.TrafficMonitor.Enabled = true
	h, err := NewClientHistory(filepath.Join(t.TempDir(), "history.sqlite"), nil, nil, func() *config.Config { return cfg })
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	now := time.Now().UTC().Truncate(time.Second)
	a := ClientCounter{ID: "a", Name: "Device", Address: "192.0.2.2", RX: 100, TX: 200}
	if err = h.persist(now, []ClientCounter{a}); err != nil {
		t.Fatal(err)
	}
	h.publishLive(now, []ClientCounter{a})
	if len(h.Live().Points) != 0 {
		t.Fatal("first sample invented traffic")
	}
	if h.sampleInterval(time.Now()) != ClientLiveInterval {
		t.Fatal("no live lease")
	}
	if h.sampleInterval(time.Now().Add(16*time.Second)) != HistoryInterval {
		t.Fatal("lease never expires")
	}
	for n := 1; n <= 6; n++ {
		a.RX += 100
		a.TX += 50
		h.publishLive(now.Add(time.Duration(n)*5*time.Second), []ClientCounter{a})
	}
	live := h.Live()
	if len(live.Points) != 1 || live.Points[0].RX != 160 || live.Points[0].TX != 80 {
		t.Fatal(live)
	}
	var count int
	if err = h.db.QueryRow("SELECT COUNT(*) FROM traffic").Scan(&count); err != nil || count != 0 {
		t.Fatal("live wrote history", count, err)
	}
	if err = h.persist(now.Add(30*time.Second), []ClientCounter{a}); err != nil {
		t.Fatal(err)
	}
	report, err := h.Report(context.Background(), now.Add(-time.Second), now.Add(time.Minute), nil, false)
	if err != nil || len(report.Clients) != 1 || report.Clients[0].RX != 600 || report.Clients[0].TX != 300 {
		t.Fatal(report, err)
	}
	cfg.TrafficMonitor.Enabled = false
	if h.Live().Enabled {
		t.Fatal("disabled monitor still live")
	}
}
func TestLiveResetOwnerAndMultipleAddresses(t *testing.T) {
	h := &ClientHistory{}
	now := time.Now()
	a := ClientCounter{ID: "a", Address: "192.0.2.2", RX: 1000}
	b := ClientCounter{ID: "a", Address: "2001:db8::2", RX: 2000}
	h.publishLive(now, []ClientCounter{a, b})
	a.RX += 100
	b.RX += 200
	h.publishLive(now.Add(5*time.Second), []ClientCounter{a, b})
	if len(h.liveSnapshot.Points) != 1 || h.liveSnapshot.Points[0].RX != 480 {
		t.Fatal(h.liveSnapshot)
	}
	a.RX = 5
	b.ID = "new-owner"
	h.publishLive(now.Add(10*time.Second), []ClientCounter{a, b})
	if len(h.liveSnapshot.Points) != 0 {
		t.Fatal("reset/reassigned bytes counted", h.liveSnapshot)
	}
	h.publishLive(now.Add(5*time.Minute), []ClientCounter{a, b})
	if len(h.liveSnapshot.Points) != 0 {
		t.Fatal("gap presented as live", h.liveSnapshot)
	}
}
