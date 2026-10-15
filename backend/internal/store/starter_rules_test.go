package store

import (
	"github.com/netos-router/netos/internal/config"
	"path/filepath"
	"testing"
)

func TestDeletedStarterRulesStayDeletedAfterDatabaseReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "netos.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Firewall.Rules = []config.FirewallRule{}
	id, err := st.CreateRevision(cfg, "test", "explicit empty firewall")
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	if err = st.MarkActive(id); err != nil {
		st.Close()
		t.Fatal(err)
	}
	if err = st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rev, err := st.ActiveRevision()
	if err != nil {
		t.Fatal(err)
	}
	if len(rev.Config.Firewall.Rules) != 0 {
		t.Fatal("deleted starter rules were recreated after database reopen")
	}
}
