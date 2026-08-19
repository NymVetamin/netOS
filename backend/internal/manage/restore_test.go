package manage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
		if spec.name == "systemctl" && len(spec.args) > 0 && spec.args[0] == "start" {
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
	for _, path := range []string{older, newer} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
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
	if err := os.MkdirAll(m.BackupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(m.BackupDir, "netos-backup-20260101-000000.tar.gz")
	if err := os.WriteFile(backup, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Архивировать нечего, если каталогов состояния нет: tar в этом случае не
	// запускается вовсе, и проверять было бы нечего.
	if err := os.MkdirAll(m.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}

	var order []string
	m.Run = func(_ context.Context, spec command) error {
		if spec.name != "tar" {
			return nil
		}
		switch {
		case contains(spec.args, "-czf"):
			order = append(order, "backup")
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
