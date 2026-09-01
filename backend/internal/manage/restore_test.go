package manage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func writeTestBackup(t *testing.T, entries []tar.Header) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for i := range entries {
		h := entries[i]
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg && h.Size > 0 {
			if _, err := tw.Write(bytes.Repeat([]byte{'x'}, int(h.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := os.WriteFile(name, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestBackupArchiveValidationRejectsTraversalAndLinks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header tar.Header
	}{
		{"traversal", tar.Header{Name: "var/lib/netos/../../../etc/shadow", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg}},
		{"absolute", tar.Header{Name: "/etc/shadow", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg}},
		{"symlink", tar.Header{Name: "var/lib/netos/link", Linkname: "/etc", Mode: 0o777, Typeflag: tar.TypeSymlink}},
		{"foreign", tar.Header{Name: "etc/systemd/system/evil.service", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateBackupArchive(writeTestBackup(t, []tar.Header{tc.header})); err == nil {
				t.Fatal("unsafe archive was accepted")
			}
		})
	}
}

func TestBackupArchiveValidationAcceptsOwnedFiles(t *testing.T) {
	name := writeTestBackup(t, []tar.Header{
		{Name: "var/lib/netos/", Mode: 0o700, Typeflag: tar.TypeDir},
		{Name: "var/lib/netos/netos.db", Mode: 0o600, Size: 4, Typeflag: tar.TypeReg},
		{Name: "etc/netos/tls/panel.crt", Mode: 0o644, Size: 4, Typeflag: tar.TypeReg},
	})
	if err := validateBackupArchive(name); err != nil {
		t.Fatal(err)
	}
}

// Обновление до версии, которая уже стоит, — это несколько минут загрузки и
// перезапуск службы ради нулевого результата. Проверка должна быть настоящей,
// а не обещанием в справке.
func TestUpdateSkipsWhenInstalledVersionIsAlreadyLatest(t *testing.T) {
	m, out := testManager()
	m.Output = func(_ context.Context, name string, args ...string) (string, error) {
		return "https://github.com/NymVetamin/netOS/releases/tag/v1.2.3", nil
	}
	started := false
	m.Run = func(_ context.Context, spec command) error {
		if spec.name == "bash" {
			started = true
		}
		return nil
	}
	if err := m.Execute(context.Background(), []string{"update"}); err != nil {
		t.Fatal(err)
	}
	if started {
		t.Fatal("установщик запущен, хотя версия уже последняя")
	}
	if !strings.Contains(out.String(), "уже установленная версия") {
		t.Fatalf("администратору не сказали, почему ничего не произошло: %q", out.String())
	}
}

// За reinstall приходят, когда установка развалилась: отказ «у вас уже
// последняя» — ровно то, чего от этой команды не ждут.
func TestReinstallIgnoresVersionCheck(t *testing.T) {
	m, _ := testManager()
	m.Output = func(context.Context, string, ...string) (string, error) {
		return "https://github.com/NymVetamin/netOS/releases/tag/v1.2.3", nil
	}
	started := false
	m.Run = func(_ context.Context, spec command) error {
		if spec.name == "bash" {
			started = true
		}
		return nil
	}
	if err := m.Execute(context.Background(), []string{"reinstall"}); err != nil {
		t.Fatal(err)
	}
	if !started {
		t.Fatal("reinstall отказался разворачивать установленную версию")
	}
}

func TestUpdateForceIgnoresVersionCheck(t *testing.T) {
	m, _ := testManager()
	m.Output = func(context.Context, string, ...string) (string, error) {
		return "https://github.com/NymVetamin/netOS/releases/tag/v1.2.3", nil
	}
	started := false
	m.Run = func(_ context.Context, spec command) error {
		if spec.name == "bash" {
			started = true
		}
		return nil
	}
	if err := m.Execute(context.Background(), []string{"update", "--force"}); err != nil {
		t.Fatal(err)
	}
	if !started {
		t.Fatal("--force не заставил развернуть версию заново")
	}
}

// Резервная копия занимает место и время, и решение принимает владелец машины.
func TestResetAsksAboutBackup(t *testing.T) {
	m, out := testManager()
	sandbox(t, m)
	m.In = strings.NewReader("y\nn\n") // сброс — да, копия — нет

	var archived bool
	m.Run = func(_ context.Context, spec command) error {
		if spec.name == "tar" {
			archived = true
		}
		return nil
	}
	if err := m.Execute(context.Background(), []string{"reset"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "резервную копию") {
		t.Fatalf("про копию не спросили: %q", out.String())
	}
	if archived {
		t.Fatal("копия создана вопреки отказу")
	}
}

func TestResetNoBackupFlagSkipsArchive(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	var archived bool
	m.Run = func(_ context.Context, spec command) error {
		if spec.name == "tar" {
			archived = true
		}
		return nil
	}
	if err := m.Execute(context.Background(), []string{"reset", "--yes", "--no-backup"}); err != nil {
		t.Fatal(err)
	}
	if archived {
		t.Fatal("--no-backup не отменил резервную копию")
	}
}

func TestResetRemovesAppliedRuntimeBeforeForgettingConfiguration(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	unit := filepath.Join(m.Root, "etc/systemd/system/netos-xray-ch7.service")
	link := filepath.Join(m.Root, "sys/class/net/tun-ch7")
	ownership := filepath.Join(m.Root, "etc/systemd/networkd.conf.d/99-netos.conf")
	resolv := filepath.Join(m.Root, "etc/resolv.conf")
	resolvState := filepath.Join(m.StateDir, "resolv-conf.state")
	for _, path := range []string{unit, ownership} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(link, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(resolvState), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resolv, []byte("nameserver 127.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resolvState,
		[]byte(`{"kind":"file","content":"nameserver 192.0.2.53\n","resolved_enabled":false}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var commands []command
	m.Run = func(_ context.Context, spec command) error {
		commands = append(commands, spec)
		return nil
	}
	if err := m.Execute(context.Background(), []string{"reset", "--yes", "--no-backup"}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{unit, ownership} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("после сброса остался %s", path)
		}
	}
	if data, err := os.ReadFile(resolv); err != nil || string(data) != "nameserver 192.0.2.53\n" {
		t.Fatalf("системный resolv.conf не восстановлен: %q, %v", data, err)
	}
	var stoppedUnit, removedLink bool
	for _, spec := range commands {
		if spec.name == "systemctl" && contains(spec.args, "netos-xray-ch7.service") && contains(spec.args, "--now") {
			stoppedUnit = true
		}
		if spec.name == "ip" && contains(spec.args, "delete") && contains(spec.args, "tun-ch7") {
			removedLink = true
		}
	}
	if !stoppedUnit || !removedLink {
		t.Fatalf("runtime не снят: unit=%v link=%v commands=%#v", stoppedUnit, removedLink, commands)
	}
}

// Администратор стоит перед терминалом ровно затем, чтобы узнать пароль.
// Отправлять его читать файл — лишний шаг.
func TestResetPrintsCredentialsOnScreen(t *testing.T) {
	m, out := testManager()
	sandbox(t, m)
	if err := os.MkdirAll(m.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	credentials := filepath.Join(m.StateDir, "initial-credentials")
	m.Run = func(_ context.Context, spec command) error {
		// Демон заводит учётную запись при запуске — подделываем этот момент.
		if spec.name == "systemctl" && len(spec.args) > 0 &&
			(spec.args[0] == "start" || spec.args[0] == "enable") {
			return os.WriteFile(credentials,
				[]byte("Пользователь:  admin\nПароль:        Sekret123456\n"), 0o600)
		}
		return nil
	}
	if err := m.Execute(context.Background(), []string{"reset", "--yes", "--no-backup"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Sekret123456") {
		t.Fatalf("пароль не напечатан: %q", out.String())
	}
	if _, err := os.Stat(credentials); err == nil {
		t.Fatal("прочитанный пароль остался лежать на диске открытым текстом")
	}
}

// Резервные копии без восстановления — половина механизма.
func TestRestoreUnpacksChosenBackup(t *testing.T) {
	m, out := testManager()
	sandbox(t, m)
	if err := os.MkdirAll(m.BackupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	older := filepath.Join(m.BackupDir, "netos-backup-20260101-000000.tar.gz")
	newer := filepath.Join(m.BackupDir, "netos-reset-20260202-000000.tar.gz")
	valid, err := os.ReadFile(writeTestBackup(t, []tar.Header{{Name: "var/lib/netos/netos.db", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg}}))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{older, newer} {
		if err := os.WriteFile(path, valid, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Время файлов задаётся явно: копии создаются в один и тот же миг, и
	// порядок в списке иначе зависел бы от разрешения времени файловой системы.
	if err := os.Chtimes(older, time.Time{}, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(newer, time.Time{}, time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	m.In = strings.NewReader("2\ny\n") // вторая по свежести — то есть older

	var unpacked string
	m.Run = func(_ context.Context, spec command) error {
		if spec.name == "tar" && contains(spec.args, "-xzf") {
			unpacked = spec.args[len(spec.args)-1]
		}
		if spec.name == "systemctl" && contains(spec.args, "start") {
			if err := os.MkdirAll(filepath.Dir(m.sys(runtimeReadyPath)), 0o755); err != nil {
				return err
			}
			return os.WriteFile(m.sys(runtimeReadyPath), []byte("1\n"), 0o644)
		}
		return nil
	}
	if err := m.Execute(context.Background(), []string{"restore"}); err != nil {
		t.Fatal(err)
	}
	if unpacked != older {
		t.Fatalf("распакована не выбранная копия: %q", unpacked)
	}
	if !strings.Contains(out.String(), filepath.Base(newer)) {
		t.Fatalf("список копий не показан: %q", out.String())
	}
}

// Вернуться после неудачного восстановления должно быть куда.
func TestRestoreSavesStateBeforeUnpacking(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	var auditedBackup string
	m.RecordRestoreAudit = func(backup string) error {
		auditedBackup = backup
		return nil
	}
	if err := os.MkdirAll(m.BackupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(m.BackupDir, "netos-backup-20260101-000000.tar.gz")
	valid, err := os.ReadFile(writeTestBackup(t, []tar.Header{{Name: "var/lib/netos/netos.db", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg}}))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	// Архивировать нечего, если каталогов состояния нет: tar в этом случае не
	// запускается вовсе, и проверять было бы нечего.
	if err := os.MkdirAll(m.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}

	var order []string
	m.Run = func(_ context.Context, spec command) error {
		if spec.name == "systemctl" && contains(spec.args, "start") {
			if err := os.MkdirAll(filepath.Dir(m.sys(runtimeReadyPath)), 0o755); err != nil {
				return err
			}
			return os.WriteFile(m.sys(runtimeReadyPath), []byte("1\n"), 0o644)
		}
		if spec.name != "tar" {
			return nil
		}
		switch {
		case contains(spec.args, "-czf"):
			order = append(order, "backup")
			for i, arg := range spec.args {
				if arg == "-czf" && i+1 < len(spec.args) {
					if err := os.WriteFile(spec.args[i+1], []byte("mock archive"), 0o666); err != nil {
						return err
					}
				}
			}
		case contains(spec.args, "-xzf"):
			order = append(order, "restore")
		}
		return nil
	}
	if err := m.Execute(context.Background(), []string{"restore", "--yes"}); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "backup" || order[1] != "restore" {
		t.Fatalf("состояние до восстановления не сохранено первым: %v", order)
	}
	if auditedBackup != backup {
		t.Fatalf("restore completion audit target=%q, want %q", auditedBackup, backup)
	}
	if runtime.GOOS != "windows" {
		matches, _ := filepath.Glob(filepath.Join(m.BackupDir, "netos-before-restore-*.tar.gz"))
		if len(matches) != 1 {
			t.Fatalf("страховочная копия не найдена: %v", matches)
		}
		info, err := os.Stat(matches[0])
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("права страховочной копии: %v", info.Mode().Perm())
		}
	}
}

func TestRestoreWithoutBackupsExplainsWhy(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
	err := m.Execute(context.Background(), []string{"restore"})
	if err == nil || !strings.Contains(err.Error(), "нет ни одной резервной копии") {
		t.Fatalf("восстановление без копий вернуло %v", err)
	}
}

// Дополнение генерируется тем же бинарником, что и команды: список не должен
// разъезжаться со справкой.
func TestCompletionListsEveryCommand(t *testing.T) {
	m, out := testManager()
	if err := m.Execute(context.Background(), []string{"completion"}); err != nil {
		t.Fatal(err)
	}
	script := out.String()
	if !strings.Contains(script, "complete -F _netos netos") {
		t.Fatalf("это не скрипт дополнения: %q", script)
	}
	for _, command := range []string{"status", "plan", "render", "backup", "restore", "update", "reset", "uninstall"} {
		if !strings.Contains(script, command) {
			t.Fatalf("дополнение не знает команду %q", command)
		}
	}
	for _, artifact := range renderableArtifacts {
		if !strings.Contains(script, artifact) {
			t.Fatalf("дополнение не знает артефакт %q", artifact)
		}
	}
}
