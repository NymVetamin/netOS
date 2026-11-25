package vpnservers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

// Блок netOS — только целые строки «# BEGIN/END netos-l2tp-srv<число>».
// Поиск по префиксу удалял чужой блок netos-l2tp-srv7-backup вместе с его
// учётными записями, а дописанный перевод строки менял чужой хвост файла.
func TestL2TPChapRemovesOnlyExactManagedBlocks(t *testing.T) {
	ours := "# BEGIN netos-l2tp-srv7\n\"alice\" \"netos-l2tp-srv7\" \"pw\" *\n# END netos-l2tp-srv7\n"
	foreign := "# BEGIN netos-l2tp-srv7-backup\n\"bob\" * \"keep\" *\n# END netos-l2tp-srv7-backup\n" +
		"x # BEGIN netos-l2tp-srv8\n" + // не с начала строки — не маркер
		"\"carol\" * \"tail\" *" // последняя строка без перевода
	path := filepath.Join(t.TempDir(), "chap-secrets")
	if err := os.WriteFile(path, []byte(ours+foreign), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveL2TPChapSecrets(path); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != foreign {
		t.Fatalf("uninstall left %q, want %q", data, foreign)
	}
	removed, err := updateL2TPChap([]byte(ours+foreign), config.VPNServer{Index: 7}, false)
	if err != nil || string(removed) != foreign {
		t.Fatalf("remove left %q, %v; want %q", removed, err, foreign)
	}
}
