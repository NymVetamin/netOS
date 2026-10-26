package api

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func historyFrame(at, value float64) realtimeSnapshot {
	tx := value / 2
	return realtimeSnapshot{At: at, Values: []realtimeValue{{ID: "if:test", Name: "test", At: at, RXBPS: &value, TXBPS: &tx}}}
}

func TestSecondHistoryFullWeek(t *testing.T) {
	if os.Getenv("NETOS_SECOND_HISTORY_SCALE") != "1" {
		t.Skip("explicit disk scale test")
	}
	path := filepath.Join(t.TempDir(), "week.sqlite")
	h, err := openSecondHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.close() }()
	const base = 1700000000.0
	started := time.Now()
	for minute := 0; minute < 10080; minute++ {
		h.tail = nil
		for second := 0; second < 60; second++ {
			at := base + float64(minute*60+second)
			f := realtimeSnapshot{At: at}
			for client := 0; client < 3; client++ {
				rx := float64((minute*7919 + second*104729 + client*31) % 10000000)
				tx := rx / 17
				f.Values = append(f.Values, realtimeValue{ID: fmt.Sprintf("client:%d", client), Name: "QA", At: at, RXBPS: &rx, TXBPS: &tx, Seconds: 1})
			}
			h.tail = append(h.tail, f)
		}
		if err = h.flushLocked(); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("generated 604800 seconds / 3 series in %s", time.Since(started))
	for _, span := range []float64{180, 300, 604800} {
		start := time.Now()
		rows, step, e := h.window(context.Background(), base+604800-span, base+604799)
		if e != nil {
			t.Fatal(e)
		}
		t.Logf("window %.0fs: %d frames step %d, query %s", span, len(rows), step, time.Since(start))
		if span <= 300 && len(rows) != int(span) {
			t.Fatal("lost seconds", len(rows))
		}
		if span > 300 && len(rows) > 1440 {
			t.Fatal("unbounded overview")
		}
	}
	if err = h.close(); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	t.Logf("database bytes %d", info.Size())
	h, err = openSecondHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []float64{base + 1, base + 302400, base + 604798} {
		rows, step, e := h.window(context.Background(), at, at+1)
		if e != nil || step != 1 || len(rows) != 2 || rows[0].At != at {
			t.Fatal("raw second lookup after reopen", e, len(rows))
		}
	}
}

func TestSecondHistoryRestartTailAndOverlap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seconds.sqlite")
	h, err := openSecondHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 125; i++ {
		if err = h.append(historyFrame(1000+float64(i), float64(i))); err != nil {
			t.Fatal(err)
		}
	}
	verify := func(h *secondHistory, count int) {
		t.Helper()
		rows, step, e := h.window(context.Background(), 1000, 1200)
		if e != nil {
			t.Fatal(e)
		}
		if len(rows) != count || step != 1 {
			t.Fatalf("count %d step %d", len(rows), step)
		}
		for i, row := range rows {
			if row.At != 1000+float64(i) || *row.Values[0].RXBPS != float64(i) {
				t.Fatal("lost or duplicate second", i, row)
			}
		}
	}
	verify(h, 125)
	if err = h.close(); err != nil {
		t.Fatal(err)
	}
	h, err = openSecondHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.close() }()
	verify(h, 125)
	if err = h.append(historyFrame(1125, 125)); err != nil {
		t.Fatal(err)
	}
	verify(h, 126)
}

func TestSecondHistoryRetainsFailuresAndPrunesSevenDays(t *testing.T) {
	h, err := openSecondHistory(filepath.Join(t.TempDir(), "seconds.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.close() }()
	if err = h.append(historyFrame(1000, 1)); err != nil {
		t.Fatal(err)
	}
	gap := historyFrame(1001, 0)
	gap.Values[0].RXBPS = nil
	if err = h.append(gap); err != nil {
		t.Fatal(err)
	}
	rows, _, err := h.window(context.Background(), 1000, 1003)
	if err != nil || len(rows) != 2 || rows[1].Values[0].RXBPS != nil {
		t.Fatal("gap was replaced", err, rows)
	}
	if err = h.append(historyFrame(1000+7*86400+61, 1)); err != nil {
		t.Fatal(err)
	}
	rows, _, err = h.window(context.Background(), 1000, 1003)
	if err != nil || len(rows) != 0 {
		t.Fatal("expired block retained", err, len(rows))
	}
}

func TestSecondHistoryWindowCancellation(t *testing.T) {
	h, err := openSecondHistory(filepath.Join(t.TempDir(), "seconds.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.close() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err = h.window(ctx, 0, 10); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestSecondHistoryReaderDoesNotBlockSampler(t *testing.T) {
	h, err := openSecondHistory(filepath.Join(t.TempDir(), "seconds.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	if err = h.append(historyFrame(1000, 1)); err != nil {
		t.Fatal(err)
	}
	// Keep a real SQLite read transaction open, as window does while decoding.
	rows, err := h.reader.Query(`SELECT summary FROM seconds`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("missing persisted sample", rows.Err())
	}
	done := make(chan error, 1)
	go func() { done <- h.append(historyFrame(1011, 2)) }()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		rows.Close()
		<-done
		t.Fatal("sampler waited for the history reader")
	}
	// Another reader waits for this bounded pool, but honours cancellation.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, _, err = h.window(ctx, 1000, 1011); err == nil {
		t.Fatal("waiting reader ignored cancellation")
	}
	rows.Close()
	frames, step, err := h.window(context.Background(), 1000, 1011)
	if err != nil || step != 1 || len(frames) != 2 {
		t.Fatalf("retry after cancellation: frames=%d step=%d err=%v", len(frames), step, err)
	}
	if frames[1].At != 1011 || *frames[1].Values[0].RXBPS != 2 {
		t.Fatal("concurrent flush lost the new sample", frames)
	}
}

func TestSecondHistorySummaryWeightsAndPeaks(t *testing.T) {
	a, b := historyFrame(1, 100), historyFrame(11, 1000)
	a.Values[0].Seconds = 10
	b.Values[0].Seconds = 1
	value := summarize([]realtimeSnapshot{a, b}).Values[0]
	if *value.RXBPS != 2000.0/11 || value.Seconds != 11 || *value.RXPeak != 1000 {
		t.Fatal(value)
	}
	merged := summarize([]realtimeSnapshot{summarize([]realtimeSnapshot{a}), summarize([]realtimeSnapshot{b})}).Values[0]
	if *merged.RXBPS != *value.RXBPS || *merged.RXPeak != 1000 {
		t.Fatal("overview changed weights or hid peak")
	}
}
