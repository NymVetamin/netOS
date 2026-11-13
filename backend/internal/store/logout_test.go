package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLogoutSessionAtomicFailureRetryAndReopen(t *testing.T) {
	for _, table := range []string{"sessions", "audit"} {
		t.Run(table, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "logout.db")
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { s.Close() }()
			for _, token := range []string{"secret-token", "other-token"} {
				if _, err := s.CreateSession(token, "alice", "192.0.2.1", time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			event := "INSERT"
			if table == "sessions" {
				event = "DELETE"
			}
			if _, err := s.db.Exec("CREATE TRIGGER fail_logout BEFORE " + event + " ON " + table + " BEGIN SELECT RAISE(ABORT,'fixture failure'); END"); err != nil {
				t.Fatal(err)
			}
			if err := s.LogoutSession(context.Background(), "secret-token", "192.0.2.2"); err == nil {
				t.Fatal("write failure ignored")
			}
			if _, err := s.SessionUser("secret-token"); err != nil {
				t.Fatal("failed logout revoked session", err)
			}
			rows, err := s.ListAccessAudit(context.Background(), 300)
			if err != nil || len(rows) != 0 {
				t.Fatal("false event", rows, err)
			}
			if _, err := s.db.Exec("DROP TRIGGER fail_logout"); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if err := s.LogoutSession(context.Background(), "secret-token", "192.0.2.2"); err != nil {
					t.Fatal(err)
				}
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.SessionUser("secret-token"); !errors.Is(err, ErrNotFound) {
				t.Fatal("session remained", err)
			}
			if user, err := s.SessionUser("other-token"); err != nil || user != "alice" {
				t.Fatal("other session changed", user, err)
			}
			rows, err = s.ListAccessAudit(context.Background(), 300)
			if err != nil || len(rows) != 1 {
				t.Fatal(rows, err)
			}
			e := rows[0]
			if e.Action != "logout" || e.User != "alice" || e.SourceIP != "192.0.2.2" || !e.Success || e.At.IsZero() || strings.Contains(e.Detail+e.Target, "token") {
				t.Fatal(e)
			}
		})
	}
}

func TestLogoutSessionConcurrentAndCancelled(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "logout.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.CreateSession("secret-token", "alice", "192.0.2.1", time.Hour); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.LogoutSession(ctx, "secret-token", "192.0.2.2"); err == nil {
		t.Fatal("cancel ignored")
	}
	if _, err := s.SessionUser("secret-token"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.LogoutSession(context.Background(), "secret-token", "192.0.2.2"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	rows, err := s.ListAccessAudit(context.Background(), 300)
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
}

func TestLogoutSessionStorageFullRollsBack(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "logout.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.CreateSession("secret-token", "alice", "192.0.2.1", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TABLE quota_fixture(data BLOB)`); err != nil {
		t.Fatal(err)
	}
	var pages int
	if err := s.db.QueryRow(`PRAGMA page_count`).Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", pages)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TEMP TRIGGER force_full BEFORE INSERT ON audit BEGIN INSERT INTO quota_fixture VALUES(zeroblob(1048576)); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.LogoutSession(context.Background(), "secret-token", "192.0.2.2"); !IsStorageFull(err) {
		t.Fatal("expected real SQLite full error", err)
	}
	if _, err := s.SessionUser("secret-token"); err != nil {
		t.Fatal("full database revoked session", err)
	}
	rows, err := s.ListAccessAudit(context.Background(), 300)
	if err != nil || len(rows) != 0 {
		t.Fatal("full database wrote a false event", rows, err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER force_full`); err != nil {
		t.Fatal(err)
	}
	if err := s.LogoutSession(context.Background(), "secret-token", "192.0.2.2"); err != nil {
		t.Fatal("retry", err)
	}
	rows, err = s.ListAccessAudit(context.Background(), 300)
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
}

func BenchmarkLogoutSession(b *testing.B) {
	for _, n := range []int{30, 10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s, err := Open(filepath.Join(b.TempDir(), "logout.db"))
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			if _, err := s.db.Exec(`WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?) INSERT INTO audit(at,user,action,success) SELECT i,'alice','login',1 FROM n`, n); err != nil {
				b.Fatal(err)
			}
			if n > 30 {
				if _, err := s.db.Exec(`WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<1000) INSERT INTO sessions(token,username,created_at,expires_at) SELECT 'other-'||i,'alice',0,9999999999 FROM n`); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				if _, err := s.db.Exec(`INSERT INTO sessions(token,username,created_at,expires_at) VALUES('bench','alice',0,9999999999)`); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				if err := s.LogoutSession(context.Background(), "bench", "192.0.2.2"); err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				// Keep the same history size on every measured operation.
				if _, err := s.db.Exec(`DELETE FROM audit WHERE id=(SELECT MAX(id) FROM audit)`); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
			}
		})
	}
}
