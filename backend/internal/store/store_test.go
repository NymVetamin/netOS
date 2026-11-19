package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"
)

func TestSessionExpiryAndUserLimitInOneTransaction(t *testing.T) {
	st := openTestStore(t)
	for i := 0; i < 20; i++ {
		if _, err := st.CreateSession(fmt.Sprintf("active-%02d", i), "admin", "", time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.CreateSession("other-live", "viewer", "", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSession("expired", "viewer", "", -time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := st.CreateSession("other-live", "admin", "", time.Hour); err == nil || got != nil {
		t.Fatalf("duplicate live token: evicted=%v, err=%v", got, err)
	}
	got, err := st.CreateSession("new", "admin", "", time.Hour)
	if err != nil || !slices.Equal(got, []string{"expired", "active-00"}) {
		t.Fatalf("evicted after retry: %v, err=%v", got, err)
	}
	if _, err := st.SessionUser("active-00"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("oldest session still present: %v", err)
	}
	for token, user := range map[string]string{"other-live": "viewer", "new": "admin", "active-01": "admin"} {
		if got, err := st.SessionUser(token); err != nil || got != user {
			t.Fatalf("user for %s: %s, err=%v", token, got, err)
		}
	}
}

func TestReusedExpiredSessionTokenStaysRevoked(t *testing.T) {
	st := openTestStore(t)
	if _, err := st.CreateSession("reused", "first", "", -time.Hour); err != nil {
		t.Fatal(err)
	}
	evicted, err := st.CreateSession("reused", "second", "", time.Hour)
	if err != nil || !slices.Equal(evicted, []string{"reused"}) {
		t.Fatalf("evicted=%v, err=%v", evicted, err)
	}
	if _, err := st.SessionUser("reused"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired token regained access: %v", err)
	}
}

func TestDatabaseIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows не представляет Unix permission bits")
	}
	path := filepath.Join(t.TempDir(), "netos.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("права БД %04o, ожидались 0600", got)
	}
}

func TestSessionsAndAuditAreBounded(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "netos.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for i := 0; i < 30; i++ {
		evicted, err := st.CreateSession(fmt.Sprintf("token-%02d", i), "admin", "127.0.0.1", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if i >= 20 {
			want = 1
		}
		if len(evicted) != want {
			t.Fatalf("при входе %d вытеснено %d сессий, ожидалось %d", i, len(evicted), want)
		}
		if err := st.Audit(AuditEntry{Action: "test", Detail: fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	var sessions int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE username = 'admin'`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 20 {
		t.Fatalf("сессий %d, ожидалось 20", sessions)
	}
	if err := st.PruneAudit(10); err != nil {
		t.Fatal(err)
	}
	var audit int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM audit`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if audit != 10 {
		t.Fatalf("записей аудита %d, ожидалось 10", audit)
	}
}

func TestExpiredSessionTokensAreReportedForCSRFRemoval(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "netos.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, err := st.CreateSession("expired-on-login", "admin", "127.0.0.1", -time.Hour); err != nil {
		t.Fatal(err)
	}
	evicted, err := st.CreateSession("current", "admin", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(evicted) != 1 || evicted[0] != "expired-on-login" {
		t.Fatalf("CreateSession reported expired tokens %q, expected the old token", evicted)
	}

	if _, err := st.CreateSession("expired-on-prune", "admin", "127.0.0.1", -time.Hour); err != nil {
		t.Fatal(err)
	}
	pruned, err := st.PruneSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned) != 1 || pruned[0] != "expired-on-prune" {
		t.Fatalf("PruneSessions reported expired tokens %q, expected the old token", pruned)
	}
}
