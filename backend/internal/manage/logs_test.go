package manage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/store"
)

type auditLineWriter func([]byte) (int, error)

func (write auditLineWriter) Write(p []byte) (int, error) { return write(p) }

func TestLogsFollowPrintsEveryNewEntry(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	st, err := store.Open(m.sys(m.Database))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	appendEntry := func(detail string) {
		t.Helper()
		if err := st.Audit(store.AuditEntry{Detail: detail, Success: true}); err != nil {
			t.Fatal(err)
		}
	}
	appendEntry("older")
	appendEntry("newer")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const followTimeout = 10 * time.Second
	timer := time.AfterFunc(followTimeout, cancel)
	defer timer.Stop()
	const burst = 201
	var details []string
	m.Out = auditLineWriter(func(p []byte) (int, error) {
		fields := strings.Split(strings.TrimSuffix(string(p), "\n"), "\t")
		detail := fields[len(fields)-1]
		details = append(details, detail)
		if detail == "older" {
			// The reader cannot poll while this writer prepares the test data.
			timer.Stop()
			for i := 1; i <= burst; i++ {
				appendEntry(fmt.Sprint(i))
			}
			timer.Reset(followTimeout)
		}
		if detail == fmt.Sprint(burst) {
			cancel()
		}
		return len(p), nil
	})
	if err := m.Execute(ctx, []string{"logs", "--follow"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(details) != burst+2 || details[0] != "newer" || details[1] != "older" {
		t.Fatalf("выведено %d строк, ожидалось %d", len(details), burst+2)
	}
	for i, detail := range details[2:] {
		if detail != fmt.Sprint(i+1) {
			t.Fatalf("строка %d: %q", i+1, detail)
		}
	}
}

func TestLogsShowSameAuditEntriesAsPanel(t *testing.T) {
	m, out := testManager()
	sandbox(t, m)
	st, err := store.Open(m.sys(m.Database))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Audit(store.AuditEntry{
		User: "admin", Action: "panel-restart", Target: "panel", Detail: "ready",
		SourceIP: "192.0.2.10", Success: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	m.Run = func(context.Context, command) error {
		t.Fatal("logs must read audit without journalctl")
		return nil
	}
	if err := m.Execute(context.Background(), []string{"logs"}); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"admin", "panel-restart", "panel", "ready", "192.0.2.10", "OK"} {
		if !strings.Contains(out.String(), field) {
			t.Fatalf("audit output %q lacks %q", out.String(), field)
		}
	}
}
