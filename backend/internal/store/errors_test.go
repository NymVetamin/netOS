package store

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSessionWriteReportsSQLiteFull(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "netos.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	var pages int
	if err := st.db.QueryRow(`PRAGMA page_count`).Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(fmt.Sprintf(`PRAGMA max_page_count = %d`, pages)); err != nil {
		t.Fatal(err)
	}
	_, err = st.CreateSession(strings.Repeat("x", 64*1024), "admin", "127.0.0.1", time.Hour)
	if err == nil || !IsStorageFull(err) {
		t.Fatalf("CreateSession error = %v, want SQLITE_FULL", err)
	}
}
