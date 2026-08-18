package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDatabaseIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows не представляет Unix permission bits")
	}
	path := filepath.Join(t.TempDir(), "netos.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("права БД %04o, ожидались 0600", got)
	}
}
