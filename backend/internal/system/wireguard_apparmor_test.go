package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Профиль Ubuntu для wireguard-tools (Canonical, 2024): читать разрешено
// только /etc/wireguard, локальные дополнения подключаются необязательно.
const ubuntuWGProfile = `abi <abi/5.0>,
include <tunables/global>
profile wg /usr/bin/wg flags=(attach_disconnected){
  include <abstractions/base>
  file rw @{etc_rw}/wireguard/{,**},
  include if exists <local/wg>
}
`

type armorFixture struct {
	dir, profiles string
	calls         [][]string
	fail          error
}

func newArmorFixture(t *testing.T, loaded string) *armorFixture {
	t.Helper()
	root := t.TempDir()
	f := &armorFixture{dir: filepath.Join(root, "apparmor.d"), profiles: filepath.Join(root, "profiles")}
	if err := os.MkdirAll(filepath.Join(f.dir, "local"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "wg"), []byte(ubuntuWGProfile), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.profiles, []byte(loaded), 0o444); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *armorFixture) run(_ context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return "", f.fail
}

func (f *armorFixture) local(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.dir, "local", "wg"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(data)
}

func TestWireGuardAppArmorGrantsOnlyNetOSFilesAndKeepsMode(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"enforce", "complain"} {
		t.Run(mode, func(t *testing.T) {
			f := newArmorFixture(t, "/usr/sbin/swanctl (enforce)\nwg ("+mode+")\n")
			if err := EnsureWireGuardAppArmor(ctx, f.dir, f.profiles, "/var/lib/netos/generated", f.run); err != nil {
				t.Fatal(err)
			}
			local := f.local(t)
			for _, rule := range []string{
				`"/var/lib/netos/generated/wg-ch[0-9]*.conf" r,`,
				`"/var/lib/netos/generated/wg-srv[0-9]*.conf" r,`,
				`"/var/lib/netos/generated/.wg-sync-*" r,`,
			} {
				if !strings.Contains(local, rule) {
					t.Fatalf("нет правила %s:\n%s", rule, local)
				}
			}
			if strings.Contains(local, " w,") || strings.Contains(local, "rw,") {
				t.Fatalf("выдана запись:\n%s", local)
			}
			// Режим, выбранный администратором, сохраняется.
			want := []string{"apparmor_parser", "-r", filepath.Join(f.dir, "wg")}
			if mode == "complain" {
				want = []string{"apparmor_parser", "-r", "-C", filepath.Join(f.dir, "wg")}
			}
			if len(f.calls) != 1 || strings.Join(f.calls[0], " ") != strings.Join(want, " ") {
				t.Fatalf("перезагрузка %v, ожидалась %v", f.calls, want)
			}

			// Повтор без изменений не пишет файл и не перезагружает профиль.
			if err := EnsureWireGuardAppArmor(ctx, f.dir, f.profiles, "/var/lib/netos/generated", f.run); err != nil {
				t.Fatal(err)
			}
			if len(f.calls) != 1 {
				t.Fatalf("повтор перезагрузил профиль: %v", f.calls)
			}
		})
	}
}

func TestWireGuardAppArmorWithoutProfileDoesNothing(t *testing.T) {
	f := newArmorFixture(t, "")
	if err := os.Remove(filepath.Join(f.dir, "wg")); err != nil {
		t.Fatal(err)
	}
	if err := EnsureWireGuardAppArmor(context.Background(), f.dir, f.profiles, "/var/lib/netos/generated", f.run); err != nil {
		t.Fatal(err)
	}
	if f.local(t) != "" || len(f.calls) != 0 {
		t.Fatal("без профиля wg что-то изменено")
	}
}

func TestWireGuardAppArmorRequiresLocalInclude(t *testing.T) {
	f := newArmorFixture(t, "wg (enforce)\n")
	profile := strings.Replace(ubuntuWGProfile, "  include if exists <local/wg>\n", "", 1)
	if err := os.WriteFile(filepath.Join(f.dir, "wg"), []byte(profile), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := EnsureWireGuardAppArmor(context.Background(), f.dir, f.profiles, "/var/lib/netos/generated", f.run); err == nil {
		t.Fatal("профиль без local принят молча")
	}
}

// Профиль на диске, но не загружен — файл готовится, перезагрузки нет.
func TestWireGuardAppArmorNotLoadedSkipsReload(t *testing.T) {
	f := newArmorFixture(t, "/usr/sbin/swanctl (enforce)\nxwg (enforce)\n")
	if err := EnsureWireGuardAppArmor(context.Background(), f.dir, f.profiles, "/var/lib/netos/generated", f.run); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.local(t), "wg-ch") || len(f.calls) != 0 {
		t.Fatalf("local=%q calls=%v", f.local(t), f.calls)
	}
}

// Неудачная перезагрузка возвращает файл как был: иначе следующий вызов
// счёл бы блок уже применённым и не повторил бы попытку.
func TestWireGuardAppArmorReloadFailureRestoresAndRetries(t *testing.T) {
	f := newArmorFixture(t, "wg (enforce)\n")
	admin := "# правило администратора\n  /srv/vpn/** r,\n"
	if err := os.WriteFile(filepath.Join(f.dir, "local", "wg"), []byte(admin), 0o640); err != nil {
		t.Fatal(err)
	}
	f.fail = errors.New("parser failed")
	if err := EnsureWireGuardAppArmor(context.Background(), f.dir, f.profiles, "/var/lib/netos/generated", f.run); err == nil {
		t.Fatal("ошибка перезагрузки потеряна")
	}
	if f.local(t) != admin {
		t.Fatalf("после неудачи файл не восстановлен:\n%s", f.local(t))
	}
	f.fail = nil
	if err := EnsureWireGuardAppArmor(context.Background(), f.dir, f.profiles, "/var/lib/netos/generated", f.run); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 || !strings.HasPrefix(f.local(t), admin) {
		t.Fatalf("повтор не выполнен или правило администратора потеряно: %v\n%s", f.calls, f.local(t))
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(filepath.Join(f.dir, "local", "wg")); err != nil || info.Mode().Perm() != 0o640 {
			t.Fatalf("права файла администратора изменены: %v %v", info.Mode(), err)
		}
	}
}

func TestRemoveWireGuardAppArmorKeepsOnlyForeignContent(t *testing.T) {
	ctx := context.Background()
	// Файл создал netOS — при удалении он исчезает.
	f := newArmorFixture(t, "wg (enforce)\n")
	if err := EnsureWireGuardAppArmor(ctx, f.dir, f.profiles, "/var/lib/netos/generated", f.run); err != nil {
		t.Fatal(err)
	}
	if err := RemoveWireGuardAppArmor(ctx, f.dir, f.profiles, f.run); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "local", "wg")); !os.IsNotExist(err) {
		t.Fatalf("созданный netOS файл остался: %v", err)
	}
	if len(f.calls) != 2 {
		t.Fatalf("после удаления профиль не перезагружен: %v", f.calls)
	}

	// Файл был до netOS — остаётся его содержимое, даже пустое.
	f = newArmorFixture(t, "wg (enforce)\n")
	for _, before := range []string{"", "  /srv/vpn/** r,\n"} {
		if err := os.WriteFile(filepath.Join(f.dir, "local", "wg"), []byte(before), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := EnsureWireGuardAppArmor(ctx, f.dir, f.profiles, "/var/lib/netos/generated", f.run); err != nil {
			t.Fatal(err)
		}
		if err := RemoveWireGuardAppArmor(ctx, f.dir, f.profiles, f.run); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(f.dir, "local", "wg")); err != nil || f.local(t) != before {
			t.Fatalf("чужое содержимое %q не сохранено: %q %v", before, f.local(t), err)
		}
	}

	// Повторное удаление и удаление без файла — не ошибка.
	calls := len(f.calls)
	if err := RemoveWireGuardAppArmor(ctx, f.dir, f.profiles, f.run); err != nil || len(f.calls) != calls {
		t.Fatalf("повтор удаления: %v %v", err, f.calls)
	}
}
