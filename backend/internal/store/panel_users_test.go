package store

import (
	"errors"
	"testing"
	"time"
)

func TestPanelUserLastAdminAndSessionRevocation(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.CreateUser("admin", "hash", "admin"); err != nil {
		t.Fatal(err)
	}
	u := PanelUser{Username: "admin", Role: "limited", PanelAccess: PanelAccess{Enabled: true, Permissions: map[string]string{"clients": "manage"}}}
	if err := s.SavePanelUser(u, "", false, false, "admin", "test"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote last admin: %v", err)
	}
	if err := s.SavePanelUser(u, "", false, true, "admin", "test"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete last admin: %v", err)
	}
	current, err := s.UserByName("admin")
	if err != nil || current.Role != "admin" {
		t.Fatalf("rollback failed: %+v %v", current, err)
	}
	u.Username = "operator"
	if err := s.SavePanelUser(u, "hash", true, false, "admin", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateSession("token", "operator", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	u.Enabled = false
	if err := s.SavePanelUser(u, "", false, false, "admin", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionUser("token"); err == nil {
		t.Fatal("session survives access change")
	}
	access, err := s.PanelAccess("operator")
	if err != nil || access.Enabled || access.Permissions["clients"] != "manage" {
		t.Fatalf("access: %+v %v", access, err)
	}
	if err := s.SavePanelUser(u, "", false, true, "admin", "test"); err != nil {
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
