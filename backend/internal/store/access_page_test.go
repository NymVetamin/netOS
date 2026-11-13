package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestAccessAuditBatchSnapshotOrderAndPrune(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.db.Exec(`WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<10000) INSERT INTO audit(at,action) SELECT CASE WHEN i%3=0 THEN 1 ELSE 9999999999 END,CASE WHEN i%10=0 THEN 'login' ELSE 'config-save' END FROM n`); err != nil {
		t.Fatal(err)
	}
	rows, maxID, err := s.ReadAccessAuditBatch(context.Background(), -1, 0)
	if err != nil || maxID != 10000 || len(rows) != 501 {
		t.Fatal(maxID, len(rows), err)
	}
	if err := s.Audit(AuditEntry{Action: "login", User: "new"}); err != nil {
		t.Fatal(err)
	}
	same, fence, err := s.ReadAccessAuditBatch(context.Background(), maxID, 0)
	if err != nil || fence != maxID || len(same) != 501 || same[0].ID != rows[0].ID {
		t.Fatal("unconsumed snapshot changed", err)
	}
	before := int64(0)
	seen := map[int64]bool{}
	for page := 0; page < 4; page++ {
		batch, _, err := s.ReadAccessAuditBatch(context.Background(), maxID, before)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range batch {
			if row.ID > maxID || seen[row.ID] || row.ID%10 != 0 {
				t.Fatal(row)
			}
			seen[row.ID] = true
			before = row.ID
		}
		if len(batch) < 501 {
			break
		}
	}
	if len(seen) != 1000 {
		t.Fatal("clock changes or noise lost events", len(seen))
	}
	if err := s.PruneAudit(1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ReadAccessAuditBatch(context.Background(), maxID, before); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing anchor accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.ReadAccessAuditBatch(ctx, -1, 0); err == nil {
		t.Fatal("cancellation ignored")
	}
}
