package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

func TestAccessAuditFiltersBeforeLimitAndReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	if err = s.Audit(AuditEntry{Action: "login", User: "alice", Success: false}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<2000)
 INSERT INTO audit(at,action) SELECT i,'config-save' FROM n`); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListAccessAudit(context.Background(), 1)
	if err != nil || len(rows) != 1 || rows[0].User != "alice" || rows[0].Success {
		t.Fatal(rows, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = s.ListAccessAudit(ctx, 1); err == nil {
		t.Fatal("cancellation ignored")
	}
	if err = s.PruneAudit(100); err != nil {
		t.Fatal(err)
	}
	rows, err = s.ListAccessAudit(context.Background(), 300)
	if err != nil || len(rows) != 0 {
		t.Fatal("expired audit resurrected", rows, err)
	}
}

func BenchmarkAccessAuditRead(b *testing.B) {
	for _, n := range []int{100, 10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s, err := Open(filepath.Join(b.TempDir(), "audit.db"))
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			if _, err = s.db.Exec(`WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?)
 INSERT INTO audit(at,action,user) SELECT i,CASE WHEN i%10=0 THEN 'login' ELSE 'config-save' END,'alice' FROM n`, n); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rows, err := s.ListAccessAudit(context.Background(), 100)
				if err != nil || len(rows) != min(n/10, 100) {
					b.Fatal(rows, err)
				}
			}
		})
	}
}

func BenchmarkAccessAuditWrite(b *testing.B) {
	for _, n := range []int{100, 10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s, err := Open(filepath.Join(b.TempDir(), "audit.db"))
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			if _, err = s.db.Exec(`WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?)
 INSERT INTO audit(at,action,user) SELECT i,'login','alice' FROM n`, n); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err = s.Audit(AuditEntry{Action: "login", User: "alice", Success: true}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
