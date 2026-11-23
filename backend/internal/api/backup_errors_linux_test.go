//go:build linux

package api

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestBackupLinuxPermissions(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("run without root to exercise EACCES")
	}
	dir := t.TempDir()
	const name = "netos-backup-20260901-120000.tar.gz"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("archive-data"), 0600); err != nil {
		t.Fatal(err)
	}
	chmod := func(path string, mode os.FileMode) {
		t.Helper()
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	// Restore permissions before TempDir cleanup even when an assertion fails.
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	s, cookie, csrf := newAuthedServer(t)
	s.Maintenance = &Maintenance{BackupDir: dir}
	h := s.Routes()
	check := func(method string, want int) {
		t.Helper()
		for range 2 {
			w := serveAuthed(h, method, "/api/backups/"+name, nil, cookie, csrf)
			if w.Code != want {
				t.Fatalf("%s: status=%d want=%d body=%s", method, w.Code, want, w.Body.String())
			}
		}
	}
	checkOpenDenied := func() {
		t.Helper()
		f, err := s.Maintenance.OpenBackup(name)
		if f != nil {
			f.Close()
		}
		if !errors.Is(err, syscall.EACCES) {
			t.Fatalf("OpenBackup: expected real EACCES, got %v", err)
		}
		check(http.MethodGet, http.StatusInternalServerError)
	}
	checkDeleteDenied := func() {
		t.Helper()
		if err := s.Maintenance.DeleteBackup(name); !errors.Is(err, syscall.EACCES) {
			t.Fatalf("DeleteBackup: expected real EACCES, got %v", err)
		}
		check(http.MethodDelete, http.StatusInternalServerError)
	}
	chmod(dir, 0)
	checkOpenDenied()
	checkDeleteDenied()
	chmod(dir, 0700)
	chmod(path, 0)
	checkOpenDenied()
	chmod(path, 0600)
	chmod(dir, 0500)
	check(http.MethodGet, http.StatusOK)
	checkDeleteDenied()
	chmod(dir, 0700)
	checkBackupLinuxRecovery(t, h, cookie, csrf, name)
}

func TestBackupLinuxReadOnlyFilesystem(t *testing.T) {
	if os.Getenv("NETOS_BACKUP_LINUX_TEST") != "1" {
		t.Skip("NETOS_BACKUP_LINUX_TEST=1 in an isolated mount namespace required")
	}
	self, selfErr := os.Readlink("/proc/self/ns/mnt")
	host, hostErr := os.Readlink("/proc/1/ns/mnt")
	if os.Geteuid() != 0 || selfErr != nil || hostErr != nil || self == host {
		t.Fatal("root and a mount namespace distinct from PID 1 required")
	}
	dir := t.TempDir()
	if err := syscall.Mount("tmpfs", dir, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "size=1m"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := syscall.Unmount(dir, 0); err != nil {
			t.Errorf("unmount own tmpfs: %v", err)
		}
	})
	const name = "netos-backup-20260901-120000.tar.gz"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("archive-data"), 0600); err != nil {
		t.Fatal(err)
	}
	remount := func(readOnly bool) {
		t.Helper()
		flags := uintptr(syscall.MS_REMOUNT | syscall.MS_NOSUID | syscall.MS_NODEV)
		if readOnly {
			flags |= syscall.MS_RDONLY
		}
		if err := syscall.Mount("", dir, "", flags, ""); err != nil {
			t.Fatal(err)
		}
	}
	remount(true)
	s, cookie, csrf := newAuthedServer(t)
	s.Maintenance = &Maintenance{BackupDir: dir}
	h := s.Routes()
	if err := s.Maintenance.DeleteBackup(name); !errors.Is(err, syscall.EROFS) {
		t.Fatalf("DeleteBackup: expected real EROFS, got %v", err)
	}
	for range 2 {
		w := serveAuthed(h, http.MethodDelete, "/api/backups/"+name, nil, cookie, csrf)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("readonly DELETE: %d %s", w.Code, w.Body.String())
		}
		w = serveAuthed(h, http.MethodGet, "/api/backups/"+name, nil, cookie, csrf)
		if w.Code != http.StatusOK || w.Body.String() != "archive-data" {
			t.Fatalf("readonly GET: %d %s", w.Code, w.Body.String())
		}
	}
	remount(false)
	checkBackupLinuxRecovery(t, h, cookie, csrf, name)
}

func checkBackupLinuxRecovery(t *testing.T, h http.Handler, cookie *http.Cookie, csrf, name string) {
	t.Helper()
	for range 2 {
		w := serveAuthed(h, http.MethodGet, "/api/backups/"+name, nil, cookie, csrf)
		if w.Code != http.StatusOK || w.Body.String() != "archive-data" {
			t.Fatalf("recovered GET: %d %s", w.Code, w.Body.String())
		}
	}
	for _, want := range []int{http.StatusOK, http.StatusNotFound} {
		w := serveAuthed(h, http.MethodDelete, "/api/backups/"+name, nil, cookie, csrf)
		if w.Code != want {
			t.Fatalf("recovered DELETE: %d want %d", w.Code, want)
		}
	}
	if w := serveAuthed(h, http.MethodGet, "/api/backups/"+name, nil, cookie, csrf); w.Code != http.StatusNotFound {
		t.Fatalf("deleted GET: %d", w.Code)
	}
}
