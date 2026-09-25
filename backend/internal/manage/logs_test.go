package manage

import (
	"context"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/store"
)

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
