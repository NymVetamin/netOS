package manage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestComponentCleanupRemovesOwnedPPPHooks(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	dir := m.sys("/etc/ppp/ip-pre-up.d")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "netos-l2tp-srv30")
	if err := os.Symlink(filepath.Join(m.StateDir, "generated", "vpn-l2tp-srv30.pre-up"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	foreign := filepath.Join(dir, "netos-l2tp-srv31")
	if err := os.WriteFile(foreign, []byte("foreign"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.removeComponentUnits(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("owned hook remains after component cleanup: %v", err)
	}
	if data, err := os.ReadFile(foreign); err != nil || string(data) != "foreign" {
		t.Fatalf("foreign hook changed: %v %s", err, data)
	}
}

func TestComponentCleanupRemovesL2TPChapSecrets(t *testing.T) {
	m, out := testManager()
	sandbox(t, m)
	path := m.sys("/etc/ppp/chap-secrets")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	before := "# Secrets for authentication using CHAP\n\"bob\" * \"own\" *\n" +
		"# BEGIN netos-l2tp-srv1\n\"alice\" \"netos-l2tp-srv1\" \"pw1\" 10.0.0.2\n# END netos-l2tp-srv1\n" +
		"\"carol\" * \"foreign\" *\n" +
		"# BEGIN netos-l2tp-srv12\n\"dave\" \"netos-l2tp-srv12\" \"pw2\" 10.0.1.2\n# END netos-l2tp-srv12\n"
	if err := os.WriteFile(path, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	for range 2 { // повтор после частичного удаления не должен падать
		if err := m.removeComponentUnits(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	want := "# Secrets for authentication using CHAP\n\"bob\" * \"own\" *\n\"carol\" * \"foreign\" *\n"
	if data, err := os.ReadFile(path); err != nil || string(data) != want {
		t.Fatalf("chap-secrets = %q, %v; want %q", data, err, want)
	}

	broken := "\"bob\" * \"own\" *\n# BEGIN netos-l2tp-srv2\n\"eve\" \"netos-l2tp-srv2\" \"pw\" *\n"
	if err := os.WriteFile(path, []byte(broken), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.removeComponentUnits(context.Background()); err != nil {
		t.Fatalf("broken chap-secrets aborted cleanup: %v", err)
	}
	if !strings.Contains(out.String(), "netos-l2tp-srv2") {
		t.Fatalf("no warning about broken block: %q", out)
	}
	if data, _ := os.ReadFile(path); string(data) != broken {
		t.Fatalf("broken file changed: %q", data)
	}
}
