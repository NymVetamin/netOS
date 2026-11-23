package api

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupRoutesFilesystemFailureAndRecovery(t *testing.T) {
	s, cookie, csrf := newAuthedServer(t)
	dir := t.TempDir()
	broken := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(broken, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.Maintenance = &Maintenance{BackupDir: broken}
	h := s.Routes()
	name := "netos-backup-20260901-120000.tar.gz"
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		for range 2 {
			w := serveAuthed(h, method, "/api/backups/"+name, nil, cookie, csrf)
			if w.Code != http.StatusInternalServerError {
				t.Errorf("%s broken root: status=%d body=%s", method, w.Code, w.Body.String())
			}
		}
	}
	s.Maintenance.BackupDir = dir
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		for _, absent := range []string{name, "invalid-name"} {
			w := serveAuthed(h, method, "/api/backups/"+absent, nil, cookie, csrf)
			if w.Code != http.StatusNotFound {
				t.Fatalf("%s %s: status=%d", method, absent, w.Code)
			}
		}
	}
	path := filepath.Join(dir, name)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		if w := serveAuthed(h, method, "/api/backups/"+name, nil, cookie, csrf); w.Code != http.StatusNotFound {
			t.Fatalf("nonregular %s: %d", method, w.Code)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("archive-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		w := serveAuthed(h, http.MethodGet, "/api/backups/"+name, nil, cookie, csrf)
		if w.Code != http.StatusOK || w.Body.String() != "archive-data" {
			t.Fatalf("recovered download: %d %s", w.Code, w.Body.String())
		}
	}
	for _, want := range []int{http.StatusOK, http.StatusNotFound} {
		w := serveAuthed(h, http.MethodDelete, "/api/backups/"+name, nil, cookie, csrf)
		if w.Code != want {
			t.Fatalf("delete: %d want %d", w.Code, want)
		}
	}
}
