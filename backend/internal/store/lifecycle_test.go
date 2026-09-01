package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "state", "netos.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestDatabaseSchemaVersionIsIndependentFromConfigSchema(t *testing.T) {
	st := openTestStore(t)
	var version int
	if err := st.db.QueryRow(`SELECT version FROM schema_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Fatalf("database schema version = %d, want %d", version, schemaVersion)
	}
	if schemaVersion == config.Version {
		t.Fatalf("test requires independently moving schemas, both are %d", schemaVersion)
	}
}

func TestRevisionLoadMigratesPreviousConfigSchema(t *testing.T) {
	st := openTestStore(t)
	cfg := config.Default()
	cfg.Version = config.Version - 1
	cfg.System.Panel.Port = 0
	cfg.Firewall.OutputPolicy = ""
	id, err := st.CreateRevision(cfg, "migration-test", "previous schema")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := st.Revision(id)
	if err != nil {
		t.Fatal(err)
	}
	if revision.Config.Version != config.Version || revision.Config.System.Panel.Port != 8443 || revision.Config.Firewall.OutputPolicy != "accept" {
		t.Fatalf("previous config was not migrated on load: %+v", revision.Config)
	}
}

func TestRevisionLifecycleAndMissingIDs(t *testing.T) {
	st := openTestStore(t)
	if _, err := st.ActiveRevision(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ActiveRevision() on empty store = %v", err)
	}
	first := config.Default()
	first.System.Hostname = "first"
	id1, err := st.CreateRevision(first, "admin", "first revision")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MarkActive(id1); err != nil {
		t.Fatal(err)
	}
	second := config.Default()
	second.System.Hostname = "second"
	id2, err := st.CreateRevision(second, "admin", "second revision")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetRevisionState(id2, StateApplying); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkActive(id2); err != nil {
		t.Fatal(err)
	}

	active, err := st.ActiveRevision()
	if err != nil || active.ID != id2 || active.Config.System.Hostname != "second" || active.AppliedAt == nil {
		t.Fatalf("unexpected active revision: %#v, err=%v", active, err)
	}
	old, err := st.Revision(id1)
	if err != nil || old.State != StateSuperseded {
		t.Fatalf("old revision state = %#v, err=%v", old, err)
	}
	latest, err := st.LatestRevision()
	if err != nil || latest.ID != id2 {
		t.Fatalf("latest revision = %#v, err=%v", latest, err)
	}

	if err := st.MarkActive(999999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("MarkActive(missing) = %v", err)
	}
	stillActive, err := st.ActiveRevision()
	if err != nil || stillActive.ID != id2 {
		t.Fatalf("missing activation damaged active revision: %#v, err=%v", stillActive, err)
	}
	if err := st.SetRevisionState(999999, StateApplying); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetRevisionState(missing) = %v", err)
	}
	if _, err := st.Revision(999999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Revision(missing) = %v", err)
	}

	revisions, err := st.ListRevisions(1)
	if err != nil || len(revisions) != 1 || revisions[0].ID != id2 || revisions[0].Config != nil {
		t.Fatalf("ListRevisions(1) = %#v, err=%v", revisions, err)
	}
}

func TestPruneRevisionsKeepsActiveApplyingAndNewest(t *testing.T) {
	st := openTestStore(t)
	var ids []int64
	for i := 0; i < 12; i++ {
		cfg := config.Default()
		cfg.System.Hostname = fmt.Sprintf("router-%d", i)
		id, err := st.CreateRevision(cfg, "admin", fmt.Sprint(i))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		if err := st.SetRevisionState(id, StateRolledBack); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.MarkActive(ids[0]); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRevisionState(ids[1], StateApplying); err != nil {
		t.Fatal(err)
	}
	if err := st.PruneRevisions(2); err != nil { // minimum is intentionally five
		t.Fatal(err)
	}
	rows, err := st.ListRevisions(100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 7 {
		t.Fatalf("kept %d revisions, want newest five plus active/applying", len(rows))
	}
	for _, id := range ids[:2] {
		if _, err := st.Revision(id); err != nil {
			t.Fatalf("protected revision %d was pruned: %v", id, err)
		}
	}
}

func TestUserPasswordSessionLifecycle(t *testing.T) {
	st := openTestStore(t)
	if count, err := st.CountUsers(); err != nil || count != 0 {
		t.Fatalf("CountUsers() = %d, %v", count, err)
	}
	id, err := st.CreateUser("admin", "hash-1", "admin")
	if err != nil || id == 0 {
		t.Fatalf("CreateUser() = %d, %v", id, err)
	}
	if _, err := st.CreateUser("admin", "duplicate", "admin"); err == nil {
		t.Fatal("duplicate username was accepted")
	}
	user, err := st.UserByName("admin")
	if err != nil || user.PasswordHash != "hash-1" || user.Role != "admin" || user.LastLogin != nil {
		t.Fatalf("UserByName() = %#v, %v", user, err)
	}
	if _, err := st.UserByName("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UserByName(missing) = %v", err)
	}
	if err := st.TouchLogin("admin"); err != nil {
		t.Fatal(err)
	}
	user, _ = st.UserByName("admin")
	if user.LastLogin == nil {
		t.Fatal("TouchLogin did not set last_login")
	}
	if _, err := st.CreateSession("one", "admin", "192.0.2.1", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSession("two", "admin", "192.0.2.2", time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := st.SessionUser("one"); err != nil || got != "admin" {
		t.Fatalf("SessionUser() = %q, %v", got, err)
	}
	tokens, err := st.UpdatePasswordAndDeleteSessions("admin", "hash-2")
	if err != nil || len(tokens) != 2 {
		t.Fatalf("UpdatePasswordAndDeleteSessions() = %q, %v", tokens, err)
	}
	user, _ = st.UserByName("admin")
	if user.PasswordHash != "hash-2" {
		t.Fatalf("password hash = %q", user.PasswordHash)
	}
	for _, token := range []string{"one", "two"} {
		if _, err := st.SessionUser(token); !errors.Is(err, ErrNotFound) {
			t.Fatalf("session %q survived password change: %v", token, err)
		}
	}
	if _, err := st.UpdatePasswordAndDeleteSessions("missing", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("password update for missing user = %v", err)
	}
	if err := st.UpdatePassword("admin", "hash-3"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSession("delete-me", "admin", "", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteSession("delete-me"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SessionUser("delete-me"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted session returned %v", err)
	}
	if _, err := st.CreateSession("expired", "admin", "", -time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SessionUser("expired"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session returned %v", err)
	}
}

func TestRootPasswordResetRollsBackCredentialAndSessionsWhenAuditFails(t *testing.T) {
	st := openTestStore(t)
	if _, err := st.CreateUser("admin", "old-hash", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSession("still-valid", "admin", "local", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`CREATE TRIGGER reject_root_password_audit
		BEFORE INSERT ON audit WHEN NEW.action = 'password_reset'
		BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ResetPasswordByRoot("admin", "new-hash"); err == nil {
		t.Fatal("injected audit failure was ignored")
	}
	user, err := st.UserByName("admin")
	if err != nil || user.PasswordHash != "old-hash" {
		t.Fatalf("credential changed after rollback: %#v, %v", user, err)
	}
	if got, err := st.SessionUser("still-valid"); err != nil || got != "admin" {
		t.Fatalf("session revoked after rollback: %q, %v", got, err)
	}
}

func TestAuditDevicesAndPing(t *testing.T) {
	st := openTestStore(t)
	entries := []AuditEntry{
		{User: "admin", Action: "apply", Target: "config", Detail: "ok", SourceIP: "192.0.2.1", Success: true},
		{User: "viewer", Action: "apply", Target: "config", Detail: "denied", SourceIP: "192.0.2.2", Success: false},
	}
	for _, entry := range entries {
		if err := st.Audit(entry); err != nil {
			t.Fatal(err)
		}
	}
	audit, err := st.ListAudit(10000)
	if err != nil || len(audit) != 2 || audit[0].Detail != "denied" || audit[0].Success {
		t.Fatalf("ListAudit() = %#v, %v", audit, err)
	}
	if err := st.PruneAudit(0); err == nil {
		t.Fatal("PruneAudit(0) succeeded")
	}

	if err := st.UpsertDevice("aa:bb:cc:dd:ee:ff", "192.0.2.10", "phone"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertDevice("aa:bb:cc:dd:ee:ff", "192.0.2.11", ""); err != nil {
		t.Fatal(err)
	}
	devices, err := st.ListDevices()
	if err != nil || len(devices) != 1 || devices[0].IP != "192.0.2.11" || devices[0].Hostname != "phone" {
		t.Fatalf("ListDevices() = %#v, %v", devices, err)
	}
	if err := st.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}
