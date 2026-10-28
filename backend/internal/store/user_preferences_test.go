package store

import (
	"path/filepath"
	"testing"
)

func TestUserHintsUpgradePersistenceAndDeletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "netos.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice", "bob"} {
		if _, err := s.CreateUser(name, "hash", "viewer"); err != nil {
			t.Fatal(err)
		}
	}
	// An existing v3 database has users but no preferences table.
	if _, err := s.db.Exec(`DROP TABLE user_preferences; UPDATE schema_version SET version=3`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice", "bob"} {
		u, err := s.UserByName(name)
		if err != nil || !u.ShowHints {
			t.Fatalf("default %s: %v %v", name, u, err)
		}
	}
	if err := s.SetShowHints("alice", false); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, _ := s.UserByName("alice")
	b, _ := s.UserByName("bob")
	if a.ShowHints || !b.ShowHints {
		t.Fatal("preference lost or leaked between accounts")
	}
	if err := s.SetShowHints("missing", false); err == nil {
		t.Fatal("orphan preference accepted")
	}
	if _, err := s.db.Exec(`DELETE FROM users WHERE username='alice'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser("alice", "newhash", "viewer"); err != nil {
		t.Fatal(err)
	}
	a, err = s.UserByName("alice")
	if err != nil || !a.ShowHints {
		t.Fatal("deleted account preference survived")
	}
}
