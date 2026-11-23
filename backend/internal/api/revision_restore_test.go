package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/store"
)

func TestRestoreRevisionReadFailureAndRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revisions.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := config.Default()
	cfg.System.Hostname = "restored-router"
	id, err := st.CreateRevision(cfg, "admin", "restore")
	if err != nil {
		t.Fatal(err)
	}
	original := config.Default()
	s := &Server{Store: st, draft: original, draftVersion: 7}
	restore := func(revision int64, version uint64, want int) {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/api/revisions/restore", nil)
		r.SetPathValue("id", strconv.FormatInt(revision, 10))
		r.Header.Set("If-Match", strconv.FormatUint(version, 10))
		w := httptest.NewRecorder()
		s.handleRestoreRevision(w, r)
		if w.Code != want {
			t.Fatalf("restore: status=%d want=%d body=%s", w.Code, want, w.Body.String())
		}
	}
	restore(id+1, 7, http.StatusNotFound)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		restore(id, 7, http.StatusInternalServerError)
		if s.draft != original || s.draftVersion != 7 {
			t.Fatal("failed read changed the draft")
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/api/revisions", nil)
	r.SetPathValue("id", strconv.FormatInt(id, 10))
	w := httptest.NewRecorder()
	s.handleRevision(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("read: status=%d body=%s", w.Code, w.Body.String())
	}
	st, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Store = st
	restore(id, 7, http.StatusOK)
	if s.draft.System.Hostname != cfg.System.Hostname || s.draftVersion != 8 {
		t.Fatal("retry did not restore the revision")
	}
	restore(id, 7, http.StatusConflict)
	restore(id, 8, http.StatusOK)
	if s.draft.System.Hostname != cfg.System.Hostname || s.draftVersion != 9 {
		t.Fatal("repeated restore lost the revision")
	}
}
