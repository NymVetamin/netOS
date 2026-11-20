package manage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRestorePicksLatestBackupWithTiedMtimes(t *testing.T) {
	m, out := testManager()
	sandbox(t, m)
	if err := os.MkdirAll(m.BackupDir, 0700); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"netos-backup-20260102-000000-10.tar.gz", "netos-backup-20260102-000000-9.tar.gz",
		"netos-backup-20260102-000000-2.tar.gz", "netos-backup-20260102-000000.tar.gz",
		"netos-before-restore-20260101-000000.tar.gz", "netos-legacy.tar.gz",
	}
	same := time.Unix(1800000000, 0)
	for _, name := range want {
		path := filepath.Join(m.BackupDir, name)
		if err := os.WriteFile(path, []byte("invalid archive"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, same, same); err != nil {
			t.Fatal(err)
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		entries, err := m.listBackups()
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, entry := range entries {
			got = append(got, entry.name)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("ordered backups %v, want %v", got, want)
		}
	}
	if err := m.Execute(context.Background(), []string{"restore", "--yes"}); err == nil || !strings.Contains(out.String(), "Беру самую свежую: "+want[0]) {
		t.Fatalf("expected latest archive to be selected and rejected as invalid, err=%v", err)
	}
}

func BenchmarkListBackups(b *testing.B) {
	for _, n := range []int{32, 512} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			m := &Manager{BackupDir: b.TempDir()}
			stamp := time.Unix(1800000000, 0)
			for i := 0; i < n; i++ {
				path := filepath.Join(m.BackupDir, fmt.Sprintf("netos-backup-20260102-000000-%d.tar.gz", i+2))
				if err := os.WriteFile(path, nil, 0600); err != nil {
					b.Fatal(err)
				}
				if err := os.Chtimes(path, stamp, stamp); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if entries, err := m.listBackups(); err != nil || len(entries) != n {
					b.Fatal(len(entries), err)
				}
			}
		})
	}
}

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

func TestRestoreExplicitArchiveInLiteralDirectory(t *testing.T) {
	m, out := testManager()
	sandbox(t, m)
	m.BackupDir = filepath.Join(m.BackupDir, "[archives")
	if err := os.MkdirAll(m.BackupDir, 0700); err != nil {
		t.Fatal(err)
	}
	archive := writeTestBackup(t, []tar.Header{{Name: "var/lib/netos/netos.db", Mode: 0600, Size: 4, Typeflag: tar.TypeReg}})
	path := filepath.Join(m.BackupDir, "netos-selected.tar.gz")
	if err := os.Rename(archive, path); err != nil {
		t.Fatal(err)
	}
	for _, choice := range []string{path, filepath.Base(path)} {
		out.Reset()
		if err := m.Execute(context.Background(), []string{"restore", choice}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "netos-selected.tar.gz. Продолжить?") || !strings.Contains(out.String(), "Отменено.") {
			t.Fatal(out.String())
		}
	}
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

func validateBackupArchive(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return validateBackupContents(f)
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

func TestRestoreRejectsMissingDatabaseBeforeStoppingDaemon(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []tar.Header
	}{
		{"empty archive", nil},
		{"configuration files only", []tar.Header{{Name: "etc/netos/tls/panel.crt", Typeflag: tar.TypeReg, Size: 4, Mode: 0o600}}},
		{"database directory", []tar.Header{{Name: "var/lib/netos/netos.db", Typeflag: tar.TypeDir, Mode: 0o700}}},
		{"empty database", []tar.Header{{Name: "var/lib/netos/netos.db", Typeflag: tar.TypeReg, Mode: 0o600}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := testManager()
			sandbox(t, m)
			archive := writeTestBackup(t, tc.entries)
			var commands []string
			m.Run = func(_ context.Context, cmd command) error {
				commands = append(commands, cmd.name)
				return os.ErrPermission // Stop the reproduction before any destructive operation.
			}
			if err := m.Execute(context.Background(), []string{"restore", archive, "--yes"}); err == nil {
				t.Fatal("archive without a usable database was accepted")
			}
			if len(commands) != 0 {
				t.Fatalf("invalid backup reached service/filesystem mutation: %v", commands)
			}
		})
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
	simulateResetCredentials(t, m)
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
	simulateResetCredentials(t, m)
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
	simulateResetCredentials(t, m)
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
			if spec.stdinFile != nil {
				unpacked = spec.stdinFile.Name()
			}
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
	seedBackupDatabase(t, m)
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
	resolver := m.sys("/etc/resolv.conf")
	if err := os.MkdirAll(filepath.Dir(resolver), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resolver, []byte("# Сгенерировано netOS.\nnameserver 127.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.StateDir, "resolv-conf.state"), []byte(`{"kind":"file","content":"nameserver 192.0.2.53\n"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var order []string
	m.Run = func(_ context.Context, spec command) error {
		if spec.name == "systemctl" && contains(spec.args, "start") {
			content, _ := os.ReadFile(resolver)
			if string(content) != "nameserver 192.0.2.53\n" {
				t.Errorf("restored daemon cannot download missing components: resolver=%q", content)
			}
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
			if _, err := os.Stat(filepath.Join(m.StateDir, "resolv-conf.state")); err != nil {
				t.Errorf("resolver ownership lost before safety backup: %v", err)
			}
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

func TestRestoreRemovesCurrentRuntimeBeforeReplacingOwnership(t *testing.T) {
	m, _ := testManager()
	sandbox(t, m)
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

	unit := filepath.Join(m.Root, "etc/systemd/system/netos-hostapd-wlan0.service")
	if err := os.MkdirAll(filepath.Dir(unit), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unit, []byte("unit"), 0o644); err != nil {
		t.Fatal(err)
	}
	generated := filepath.Join(m.StateDir, "generated")
	if err := os.MkdirAll(generated, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(generated, "owned-qos.json"), []byte(`[{"interface":"eth9","ifb":"ifb-netos-0"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(generated, "owned-vpn-servers.json"), []byte(`[{"name":"wg-srv1"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"wg-srv1", "ifb-netos-0"} {
		if err := os.MkdirAll(filepath.Join(m.Root, "sys/class/net", name), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	var commands []command
	m.Run = func(_ context.Context, spec command) error {
		commands = append(commands, spec)
		if spec.name == "tar" && contains(spec.args, "-czf") {
			for i, arg := range spec.args {
				if arg == "-czf" && i+1 < len(spec.args) {
					return os.WriteFile(spec.args[i+1], []byte("mock archive"), 0o600)
				}
			}
		}
		if spec.name == "systemctl" && contains(spec.args, "start") {
			if err := os.MkdirAll(filepath.Dir(m.sys(runtimeReadyPath)), 0o755); err != nil {
				return err
			}
			return os.WriteFile(m.sys(runtimeReadyPath), []byte("1\n"), 0o644)
		}
		return nil
	}
	if err := m.Execute(context.Background(), []string{"restore", backup, "--yes"}); err != nil {
		t.Fatal(err)
	}

	var stoppedWiFi, removedWG, removedIFB, clearedQoS bool
	cleanupAt, extractAt := -1, -1
	for i, spec := range commands {
		switch {
		case spec.name == "systemctl" && contains(spec.args, "netos-hostapd-wlan0.service") && contains(spec.args, "--now"):
			stoppedWiFi = true
			if cleanupAt < 0 {
				cleanupAt = i
			}
		case spec.name == "ip" && contains(spec.args, "delete") && contains(spec.args, "wg-srv1"):
			removedWG = true
		case spec.name == "ip" && contains(spec.args, "delete") && contains(spec.args, "ifb-netos-0"):
			removedIFB = true
		case spec.name == "tc" && contains(spec.args, "eth9") && contains(spec.args, "qdisc"):
			clearedQoS = true
		case spec.name == "tar" && contains(spec.args, "-xzf") && spec.stdinFile != nil && spec.stdinFile.Name() == backup:
			extractAt = i
		}
	}
	if !stoppedWiFi || !removedWG || !removedIFB || !clearedQoS {
		t.Fatalf("runtime cleanup incomplete: wifi=%v wg=%v ifb=%v qos=%v commands=%#v", stoppedWiFi, removedWG, removedIFB, clearedQoS, commands)
	}
	if cleanupAt < 0 || extractAt < 0 || cleanupAt >= extractAt {
		t.Fatalf("runtime was not removed before backup extraction: cleanup=%d extract=%d commands=%#v", cleanupAt, extractAt, commands)
	}
}

func TestRestoreWithoutCurrentDatabaseWithRealTar(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("GNU tar and Linux archive paths")
	}
	m, _ := testManager()
	sandbox(t, m)
	seedBackupDatabase(t, m)
	m.Now = func() time.Time { return time.Unix(1800000000, 0) }
	dbPath := filepath.Join(m.StateDir, "netos.db")
	original, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	// Run the real archive commands relative to the temporary router root.
	failExtract := false
	m.Run = func(ctx context.Context, cmd command) error {
		if cmd.name == "tar" {
			args := slices.Clone(cmd.args)
			args[1] = m.Root
			for i := 4; i < len(args); i++ {
				args[i] = strings.Replace(args[i], strings.TrimPrefix(m.Root, "/")+"/", "", 1)
			}
			if failExtract && args[2] == "-xzf" {
				failExtract = false
				return fmt.Errorf("target extraction failed")
			}
			cmd.args = args
			return m.runOS(ctx, cmd)
		}
		if cmd.name == "systemctl" && cmd.args[0] == "start" {
			ready := m.sys(runtimeReadyPath)
			if err := os.MkdirAll(filepath.Dir(ready), 0755); err != nil {
				return err
			}
			return os.WriteFile(ready, nil, 0600)
		}
		return nil
	}
	archive, err := m.backup(context.Background(), "backup")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateBackupArchive(archive); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dbPath); err != nil {
		t.Fatal(err)
	}
	leftover := filepath.Join(m.StateDir, "existing-note")
	if err := os.WriteFile(leftover, []byte("keep on rollback"), 0600); err != nil {
		t.Fatal(err)
	}
	failExtract = true
	if err := m.Execute(context.Background(), []string{"restore", "--yes"}); err == nil || !strings.Contains(err.Error(), "автоматически восстановлено") {
		t.Fatalf("expected rollback, got %v", err)
	}
	if data, err := os.ReadFile(leftover); err != nil || string(data) != "keep on rollback" {
		t.Fatal("previous files lost on rollback", err)
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatal("rollback did not restore the missing-database state", err)
	}
	if err := m.Execute(context.Background(), []string{"restore", "--yes"}); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(dbPath); err != nil || !bytes.Equal(data, original) {
		t.Fatal("database differs from original", err)
	}
	if entries, err := m.listBackups(); err != nil || len(entries) != 1 || entries[0].path != archive {
		t.Fatalf("selectable backups after retry: %v, %v", entries, err)
	}
	second, err := m.backup(context.Background(), "backup")
	if err != nil || !strings.HasSuffix(second, "-2.tar.gz") {
		t.Fatalf("second backup in same second: %q %v", second, err)
	}
	for _, path := range []string{archive, second} {
		if err := validateBackupArchive(path); err != nil {
			t.Fatal(err)
		}
	}
	contents, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{m.StateDir, m.ConfigDir, m.LogDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		selected := filepath.Join(dir, "selected.tar.gz")
		if err := os.WriteFile(selected, contents, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dbPath, []byte("previous state"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := m.Execute(context.Background(), []string{"restore", selected, "--yes"}); err != nil {
			t.Fatal(err)
		}
		if data, err := os.ReadFile(dbPath); err != nil || !bytes.Equal(data, original) {
			t.Fatalf("database not restored from %s: %v", dir, err)
		}
		if _, err := os.Stat(selected); !os.IsNotExist(err) {
			t.Fatalf("old archive path survived cleanup: %s (%v)", selected, err)
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
