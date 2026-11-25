package store

import (
	"errors"
	"testing"
	"time"
)

// Журналы «Система» и «Доступ» получают аудит через OnAudit; запись, вставленная
// мимо него, появлялась там только после перезапуска netosd.
func TestPanelUserChangesReachOnAudit(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.CreateUser("admin", "hash", "admin"); err != nil {
		t.Fatal(err)
	}
	var seen []string
	s.OnAudit = func(e AuditEntry) { seen = append(seen, e.Action+" "+e.User+" "+e.Target+" "+e.SourceIP) }
	u := PanelUser{Username: "operator", Role: "limited", PanelAccess: PanelAccess{Enabled: true, Permissions: map[string]string{"clients": "manage"}}}
	if _, err := s.SavePanelUser(u, "hash", true, false, "admin", "192.0.2.5"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SavePanelUser(u, "", false, true, "admin", "192.0.2.5"); err != nil {
		t.Fatal(err)
	}
	// Отказ откатывает транзакцию и записи в журнале не оставляет.
	last := PanelUser{Username: "admin", Role: "admin", PanelAccess: PanelAccess{Enabled: true}}
	if _, err := s.SavePanelUser(last, "", false, true, "admin", "192.0.2.5"); !errors.Is(err, ErrLastAdmin) {
		t.Fatal(err)
	}
	want := []string{"panel_user_create admin operator 192.0.2.5", "panel_user_delete admin operator 192.0.2.5"}
	if len(seen) != len(want) || seen[0] != want[0] || seen[1] != want[1] {
		t.Fatalf("OnAudit saw %q, want %q", seen, want)
	}
}

func TestPanelUserLastAdminAndSessionRevocation(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.CreateUser("admin", "hash", "admin"); err != nil {
		t.Fatal(err)
	}
	u := PanelUser{Username: "admin", Role: "limited", PanelAccess: PanelAccess{Enabled: true, Permissions: map[string]string{"clients": "manage"}}}
	if _, err := s.SavePanelUser(u, "", false, false, "admin", "test"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote last admin: %v", err)
	}
	if _, err := s.SavePanelUser(u, "", false, true, "admin", "test"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete last admin: %v", err)
	}
	current, err := s.UserByName("admin")
	if err != nil || current.Role != "admin" {
		t.Fatalf("rollback failed: %+v %v", current, err)
	}
	u.Username = "operator"
	if _, err := s.SavePanelUser(u, "hash", true, false, "admin", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateSession("token", "operator", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	u.Enabled = false
	if _, err := s.SavePanelUser(u, "", false, false, "admin", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionUser("token"); err == nil {
		t.Fatal("session survives access change")
	}
	access, err := s.PanelAccess("operator")
	if err != nil || access.Enabled || access.Permissions["clients"] != "manage" {
		t.Fatalf("access: %+v %v", access, err)
	}
	if _, err := s.SavePanelUser(u, "", false, true, "admin", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserByName("operator"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted user: %v", err)
	}
}

func TestPanelAccessBackfillIsIdempotent(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.CreateUser("admin", "hash", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM panel_access`); err != nil {
		t.Fatal(err)
	}
	if err := s.migrate(); err != nil {
		t.Fatal(err)
	}
	a, err := s.PanelAccess("admin")
	if err != nil || !a.Enabled {
		t.Fatalf("backfill: %+v %v", a, err)
	}
	if _, err := s.db.Exec(`UPDATE panel_access SET enabled=0 WHERE username='admin'`); err != nil {
		t.Fatal(err)
	}
	if err := s.migrate(); err != nil {
		t.Fatal(err)
	}
	a, err = s.PanelAccess("admin")
	if err != nil || a.Enabled {
		t.Fatalf("migration reset access: %+v %v", a, err)
	}
}

func TestPanelPasswordChangeRevokesSessionWithIdenticalAccess(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.CreateUser("admin", "old-hash", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateSession("token", "admin", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	u := PanelUser{Username: "admin", Role: "admin", PanelAccess: PanelAccess{Enabled: true}}
	changed, err := s.SavePanelUser(u, "new-hash", false, false, "admin", "test")
	if err != nil || !changed {
		t.Fatalf("password change: %v, %v", changed, err)
	}
	if _, err := s.SessionUser("token"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked session: %v", err)
	}
}
