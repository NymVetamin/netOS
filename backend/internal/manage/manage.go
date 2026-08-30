// Package manage реализует пользовательскую команду netos. Демон остаётся
// внутренним процессом netosd, а повседневное управление идёт через этот CLI.
package manage

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/subsys/services"
)

const installerRepo = "NymVetamin/netOS"

// installerURL возвращает ссылку на установщик для запрошенной версии.
//
// Скрипт берётся из того же тега, что и бинарник: установщик и релиз
// развиваются вместе, и «netos update v0.05» с сегодняшним скриптом с master
// поставил бы прошлую версию сегодняшним способом. Для latest тега нет, там
// остаётся master.
func installerURL(version string) string {
	ref := "master"
	if version != "" && version != "latest" {
		ref = version
	}
	return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/install.sh", installerRepo, ref)
}

// renderableArtifacts перечисляет то, что умеет печатать netosd -render.
// Список продублирован здесь намеренно: CLI обязан отказать до запуска демона,
// а не показывать пользователю его внутреннюю ошибку.
var renderableArtifacts = []string{"iptables", "dnsmasq", "isc-dhcp", "kea-dhcp4", "unbound", "dnsproxy", "resolv", "network", "sysctl", "config"}

type command struct {
	name  string
	args  []string
	env   []string
	stdin string
	// silent прячет вывод команды. Нужен там, где неудача ожидаема и ничего не
	// значит: systemctl честно пишет «Unit NetworkManager.service not found» на
	// машине, где его нет, и это выглядело бы сбоем удаления.
	silent bool
}

type Manager struct {
	In      io.Reader
	Out     io.Writer
	Err     io.Writer
	Version string
	EUID    func() int
	Now     func() time.Time
	Run     func(context.Context, command) error
	Output  func(context.Context, string, ...string) (string, error)
	Sleep   func(time.Duration)

	// Root подставляется перед всеми системными путями. В работе он пуст, а в
	// тестах указывает на временный каталог: иначе прогон тестов удаления под
	// root снёс бы установленный netOS на самой машине сборки.
	// in — общий буферизованный ввод для всех вопросов подряд.
	//
	// Отдельный bufio.Reader на каждый вопрос читать нельзя: он забирает из
	// потока всё, что успело прийти, и следующий вопрос получает EOF вместо
	// ответа. Заметно это только там, где вопросов два — «сбросить?» и
	// «сделать копию?», — и выглядит как молча выбранный ответ по умолчанию.
	in *bufio.Reader

	Root      string
	StateDir  string
	ConfigDir string
	LogDir    string
	BackupDir string
	Binary    string
	CLI       string
	Unit      string
}

// sys возвращает системный путь с учётом Root.
func (m *Manager) sys(path string) string {
	if m.Root == "" {
		return path
	}
	return filepath.Join(m.Root, path)
}

func New(version string) *Manager {
	m := &Manager{
		In: os.Stdin, Out: os.Stdout, Err: os.Stderr,
		Version: version, EUID: effectiveUID, Now: time.Now, Sleep: time.Sleep,
		StateDir: "/var/lib/netos", ConfigDir: "/etc/netos", LogDir: "/var/log/netos",
		BackupDir: "/var/backups/netos", Binary: "/usr/local/bin/netosd",
		CLI: "/usr/local/bin/netos", Unit: "/etc/systemd/system/netosd.service",
	}
	m.Run = m.runOS
	m.Output = m.outputOS
	return m
}

func (m *Manager) Execute(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		m.help()
		return nil
	}

	switch args[0] {
	case "version", "--version", "-v":
		if len(args) != 1 {
			return fmt.Errorf("команда version не принимает параметры")
		}
		fmt.Fprintf(m.Out, "netOS %s\n", displayVersion(m.Version))
		return nil
	case "status":
		if len(args) != 1 {
			return fmt.Errorf("команда status не принимает параметры")
		}
		fmt.Fprintf(m.Out, "netOS %s\n\n", displayVersion(m.Version))
		return m.run(ctx, "systemctl", "status", "--no-pager", "netosd")
	case "logs":
		if err := onlyFlags(args[1:], "--follow", "-f"); err != nil {
			return err
		}
		// Журнал netosd доступен только root: без этой проверки обычный
		// пользователь получил бы пустой вывод и решил, что записей нет.
		if err := m.requireRoot(); err != nil {
			return err
		}
		logArgs := []string{"-u", "netosd", "--no-pager", "-n", "100"}
		if contains(args[1:], "--follow") || contains(args[1:], "-f") {
			logArgs = append(logArgs, "-f")
		}
		return m.run(ctx, "journalctl", logArgs...)
	case "start", "stop", "restart":
		if len(args) != 1 {
			return fmt.Errorf("команда %s не принимает параметры", args[0])
		}
		if err := m.requireRoot(); err != nil {
			return err
		}
		return m.run(ctx, "systemctl", args[0], "netosd")
	case "plan":
		if len(args) != 1 {
			return fmt.Errorf("команда plan не принимает параметры")
		}
		if err := m.requireRoot(); err != nil {
			return err
		}
		return m.run(ctx, m.Binary, "-plan")
	case "render":
		if err := m.requireRoot(); err != nil {
			return err
		}
		if len(args) != 2 || !contains(renderableArtifacts, args[1]) {
			return fmt.Errorf("использование: netos render %s", strings.Join(renderableArtifacts, "|"))
		}
		return m.run(ctx, m.Binary, "-render", args[1])
	case "backup":
		if len(args) != 1 {
			return fmt.Errorf("команда backup не принимает параметры")
		}
		if err := m.requireRoot(); err != nil {
			return err
		}
		return m.backupNow(ctx)
	// reinstall — синоним update: установщик и так разворачивает версию заново,
	// сохраняя данные, и отдельного поведения у переустановки нет. Имя оставлено
	// потому, что за ним приходят, когда установка развалилась.
	case "update", "reinstall":
		if err := m.requireRoot(); err != nil {
			return err
		}
		rest, force := extractFlags(args[1:], "--force", "-f")
		version, err := positionalVersion(rest)
		if err != nil {
			return err
		}
		// reinstall разворачивает версию заново по определению: за этой
		// командой приходят, когда установка развалилась, и отказ «у вас уже
		// последняя» был бы ровно тем, чего от неё не ждут.
		return m.install(ctx, version, force || args[0] == "reinstall")
	case "reset":
		if err := m.requireRoot(); err != nil {
			return err
		}
		if err := onlyFlags(args[1:], "--yes", "-y", "--backup", "--no-backup"); err != nil {
			return err
		}
		if contains(args[1:], "--backup") && contains(args[1:], "--no-backup") {
			return fmt.Errorf("--backup и --no-backup исключают друг друга")
		}
		return m.reset(ctx,
			contains(args[1:], "--yes") || contains(args[1:], "-y"),
			contains(args[1:], "--backup"), contains(args[1:], "--no-backup"))
	case "restore":
		if err := m.requireRoot(); err != nil {
			return err
		}
		rest, yes := extractFlags(args[1:], "--yes", "-y")
		if len(rest) > 1 {
			return fmt.Errorf("ожидался не более чем один файл резервной копии")
		}
		choice := ""
		if len(rest) == 1 {
			choice = rest[0]
			if strings.HasPrefix(choice, "-") {
				return fmt.Errorf("неизвестный параметр %q", choice)
			}
		}
		return m.restore(ctx, choice, yes)
	case "completion":
		shell := "bash"
		if len(args) == 2 {
			shell = args[1]
		} else if len(args) > 2 {
			return fmt.Errorf("использование: netos completion [bash]")
		}
		if shell != "bash" {
			return fmt.Errorf("дополнение поддерживается только для bash")
		}
		fmt.Fprint(m.Out, bashCompletion)
		return nil
	case "uninstall":
		if err := m.requireRoot(); err != nil {
			return err
		}
		if err := onlyFlags(args[1:], "--yes", "-y", "--keep-data"); err != nil {
			return err
		}
		return m.uninstall(ctx,
			contains(args[1:], "--yes") || contains(args[1:], "-y"),
			contains(args[1:], "--keep-data"))
	default:
		return fmt.Errorf("неизвестная команда %q; используйте netos help", args[0])
	}
}

func (m *Manager) help() {
	fmt.Fprintln(m.Out, `netOS — управление роутером

Использование:
  netos status                 состояние службы
  netos logs [-f|--follow]     последние записи журнала
  netos update [версия] [-f|--force]
                               обновить до latest или указанной версии;
                               без --force ничего не делает, если версия та же
  netos reinstall [версия]     развернуть версию заново, даже если она уже стоит
  netos reset [--backup|--no-backup] [-y|--yes]
                               сбросить настройки и пользователей к заводским
  netos backup                 создать резервную копию
  netos restore [файл] [-y|--yes]
                               восстановить из резервной копии; без файла
                               покажет список и спросит, какую брать
  netos uninstall [--keep-data] [-y|--yes]
                               удалить netOS (по умолчанию с резервной копией)
  netos start|stop|restart     управление службой
  netos plan                   что netOS изменит в живой системе, если применить
                               конфигурацию прямо сейчас
  netos render <артефакт>      вывести сгенерированный конфиг:
                               iptables, wireguard, dnsmasq, isc-dhcp, kea-dhcp4, unbound, dnsproxy,
                               resolv, network, sysctl, config
  netos completion [bash]      скрипт дополнения команд для оболочки
  netos version                версия netOS

update и reinstall сохраняют конфигурацию, пользователей и сертификаты.`)
}

// bashCompletion — скрипт дополнения. Держим его здесь, а не отдельным файлом
// в репозитории: список команд и артефактов задан рядом, и разъехаться им
// труднее. Установщик кладёт вывод в /etc/bash_completion.d/netos.
const bashCompletion = `# Дополнение команд netos. Сгенерировано: netos completion bash
_netos() {
    local cur cmd
    cur="${COMP_WORDS[COMP_CWORD]}"
    cmd="${COMP_WORDS[1]}"

    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=($(compgen -W "status logs start stop restart plan render backup restore update reinstall reset uninstall completion version help" -- "$cur"))
        return
    fi

    case "$cmd" in
        render)
            COMPREPLY=($(compgen -W "iptables wireguard dnsmasq isc-dhcp kea-dhcp4 unbound dnsproxy resolv network sysctl config" -- "$cur"))
            ;;
        logs)
            COMPREPLY=($(compgen -W "-f --follow" -- "$cur"))
            ;;
        update|reinstall)
            COMPREPLY=($(compgen -W "latest -f --force" -- "$cur"))
            ;;
        reset)
            COMPREPLY=($(compgen -W "-y --yes --backup --no-backup" -- "$cur"))
            ;;
        uninstall)
            COMPREPLY=($(compgen -W "-y --yes --keep-data" -- "$cur"))
            ;;
        restore)
            # Резервные копии видны только root, и у остальных список будет
            # пуст — это честнее, чем показывать несуществующие имена.
            COMPREPLY=($(compgen -W "-y --yes $(ls /var/backups/netos/*.tar.gz 2>/dev/null)" -- "$cur"))
            ;;
        completion)
            COMPREPLY=($(compgen -W "bash" -- "$cur"))
            ;;
        *)
            COMPREPLY=()
            ;;
    esac
}
complete -F _netos netos
`

func (m *Manager) install(ctx context.Context, version string, force bool) error {
	fromSource := os.Getenv("NETOS_FROM_SOURCE") == "1"
	resolvedVersion := version
	if !fromSource && (resolvedVersion == "" || resolvedVersion == "latest") {
		resolvedVersion = m.latestVersion(ctx)
		if resolvedVersion == "" {
			return fmt.Errorf("не удалось определить тег последнего релиза; повторите позже или укажите версию явно")
		}
	}
	name := resolvedVersion
	if name == "" {
		name = "latest"
	}

	// Обновление до версии, которая уже стоит, — это несколько минут загрузки,
	// перезапуск службы и разрыв связности ради нулевого результата. Проверяем
	// заранее, но только когда есть с чем сравнивать: у сборки из исходников
	// версия «dev» и она не сопоставима с тегом релиза.
	if !force && m.Version != "" && m.Version != "dev" {
		target := resolvedVersion
		if target != "" && sameVersion(target, m.Version) {
			fmt.Fprintf(m.Out, "netOS %s — это уже установленная версия, обновлять нечего.\n",
				displayVersion(m.Version))
			fmt.Fprintln(m.Out, "Развернуть её заново: netos update --force (или netos reinstall).")
			return nil
		}
	}

	// Наличие релиза проверяется до всего остального. Иначе первым, что видит
	// администратор, оказывается отказ curl на скачивании установщика с
	// несуществующего тега — код возврата вместо внятной причины.
	//
	// Сборка из исходников тянет весь Go и компилирует встроенный SQLite. На
	// роутере это десятки минут, а при гигабайте памяти — уход в своп до
	// полной неотзывчивости машины. Уводить туда обновление самовольно нельзя:
	// администратор просил обновиться, а не запускать сборочный конвейер на
	// работающем роутере. Поэтому отсутствие релиза — отказ с объяснением, а
	// сборка включается явно.
	if _, err := m.Output(ctx, "curl", "-4", "-fsSIL", "--retry", "2", releaseURL(resolvedVersion)); err != nil {
		if !fromSource {
			return fmt.Errorf("готового релиза %s нет. Укажите существующую версию "+
				"или соберите из исходников явно: NETOS_FROM_SOURCE=1 netos update", name)
		}
		fmt.Fprintln(m.Out, "Готового релиза для этой версии нет — собираю из исходников.")
	}

	tmp, err := os.CreateTemp("", "netos-install-*.sh")
	if err != nil {
		return err
	}
	path := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(path)

	fmt.Fprintln(m.Out, "Загружаю установщик netOS…")
	if err := m.run(ctx, "curl", "-4", "-fsSL", "--retry", "3", "-o", path, installerURL(resolvedVersion)); err != nil {
		return fmt.Errorf("не удалось загрузить установщик версии %s: %w", name, err)
	}

	var env []string
	if resolvedVersion != "" {
		env = append(env, "NETOS_VERSION="+resolvedVersion)
	}
	if fromSource {
		env = append(env, "NETOS_FROM_SOURCE=1")
	}
	return m.runEnv(ctx, env, "bash", path)
}

// latestVersion узнаёт тег последнего релиза по редиректу releases/latest.
//
// Через редирект, а не через api.github.com: у API есть лимит на анонимные
// запросы, и на роутере за общим NAT он вполне достижим — обновление начало бы
// молча считать, что версия устарела. Пустая строка означает «выяснить не
// удалось»: это не повод отказывать в обновлении.
func (m *Manager) latestVersion(ctx context.Context) string {
	out, err := m.Output(ctx, "curl", "-4", "-fsSLI", "-o", "/dev/null",
		"-w", "%{url_effective}", "--retry", "2",
		fmt.Sprintf("https://github.com/%s/releases/latest", installerRepo))
	if err != nil {
		return ""
	}
	url := strings.TrimSpace(out)
	i := strings.LastIndex(url, "/tag/")
	if i < 0 {
		return ""
	}
	tag := url[i+len("/tag/"):]
	if !validVersion(tag) {
		return ""
	}
	return tag
}

// sameVersion сравнивает теги, не придираясь к ведущей v: релиз может быть
// помечен «v0.06», а в бинарник через ldflags попасть «0.06».
func sameVersion(a, b string) bool {
	return strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v")
}

func releaseURL(version string) string {
	if version == "" || version == "latest" {
		return fmt.Sprintf("https://github.com/NymVetamin/netOS/releases/latest/download/netosd-linux-%s", runtime.GOARCH)
	}
	return fmt.Sprintf("https://github.com/NymVetamin/netOS/releases/download/%s/netosd-linux-%s", version, runtime.GOARCH)
}

// reset возвращает netOS к заводскому состоянию.
//
// withBackup и noBackup — это три разных ответа администратора, а не булев
// флаг: «сделай копию», «не делай» и «я не сказал». В последнем случае
// спрашиваем: копия занимает место и время, а решение принимает владелец
// машины.
func (m *Manager) reset(ctx context.Context, yes, withBackup, noBackup bool) error {
	if !yes && !m.confirm("Сброс удалит все настройки, историю и пользователей. Продолжить?") {
		fmt.Fprintln(m.Out, "Отменено.")
		return nil
	}

	makeBackup := true
	switch {
	case noBackup:
		makeBackup = false
	case withBackup:
		makeBackup = true
	case !yes:
		makeBackup = m.confirm("Сделать резервную копию перед сбросом?")
	}

	if err := m.stopDaemon(ctx); err != nil {
		return err
	}
	backup := ""
	if makeBackup {
		path, err := m.backup(ctx, "reset")
		if err != nil {
			_ = m.run(ctx, "systemctl", "start", "netosd")
			return err
		}
		backup = path
	}
	for _, path := range []string{m.StateDir, m.ConfigDir, m.LogDir} {
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("удаление %s: %w", path, err)
		}
	}
	if err := os.MkdirAll(filepath.Join(m.StateDir, "generated"), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(m.ConfigDir, "tls"), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(m.LogDir, 0o755); err != nil {
		return err
	}
	if err := m.run(ctx, "systemctl", "start", "netosd"); err != nil {
		if backup != "" {
			return fmt.Errorf("запуск после сброса: %w; резервная копия: %s", err, backup)
		}
		return fmt.Errorf("запуск после сброса: %w", err)
	}
	fmt.Fprintln(m.Out, "netOS сброшен.")
	if backup != "" {
		fmt.Fprintf(m.Out, "Резервная копия: %s\n", backup)
	}
	m.printCredentials()
	return nil
}

// printCredentials показывает данные первого входа на экране.
//
// Отправлять администратора читать файл незачем: он стоит перед терминалом
// ровно затем, чтобы узнать пароль, и путь к файлу — это лишний шаг. Файл
// после показа удаляется: прочитанный пароль не должен лежать на диске
// открытым текстом.
func (m *Manager) printCredentials() {
	credentials := filepath.Join(m.StateDir, "initial-credentials")
	// Файл появляется не сразу: демон сначала применяет всю конфигурацию и
	// только потом заводит учётную запись.
	for i := 0; i < 80; i++ {
		if info, err := os.Stat(credentials); err == nil && info.Size() > 0 {
			break
		}
		m.Sleep(500 * time.Millisecond)
	}
	data, err := os.ReadFile(credentials)
	if err != nil || len(data) == 0 {
		fmt.Fprintln(m.Err, "Новые данные входа ещё создаются; проверьте: netos logs -f")
		return
	}
	fmt.Fprintln(m.Out)
	fmt.Fprintln(m.Out, "Данные для входа:")
	fmt.Fprintln(m.Out)
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		fmt.Fprintln(m.Out, "  "+line)
	}
	fmt.Fprintln(m.Out)
	_ = os.Remove(credentials)
}

// backupEntry — резервная копия, найденная в каталоге.
type backupEntry struct {
	path string
	name string
	size int64
	when time.Time
}

// listBackups перечисляет копии, новыми вперёд.
func (m *Manager) listBackups() ([]backupEntry, error) {
	paths, err := filepath.Glob(filepath.Join(m.BackupDir, "netos-*.tar.gz"))
	if err != nil {
		return nil, err
	}
	var entries []backupEntry
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		entries = append(entries, backupEntry{
			path: path, name: filepath.Base(path),
			size: info.Size(), when: info.ModTime(),
		})
	}
	// Имя копии содержит дату создания, и при совпадающем времени файла
	// сортировка по имени даёт тот же порядок. Без запасного признака список
	// на файловой системе с грубым разрешением времени менялся бы от запуска к
	// запуску, а администратор выбирает копию по номеру в нём.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].when.Equal(entries[j].when) {
			return entries[i].name > entries[j].name
		}
		return entries[i].when.After(entries[j].when)
	})
	return entries, nil
}

// restore возвращает состояние из резервной копии.
//
// Копия — это /var/lib/netos, /etc/netos и /var/log/netos целиком: конфигурация,
// история ревизий, учётные записи и сертификат панели. Живая система приводится
// в соответствие обычным путём — восстановленную конфигурацию применяет netosd
// при запуске.
func (m *Manager) restore(ctx context.Context, choice string, yes bool) error {
	entries, err := m.listBackups()
	if err != nil {
		return err
	}

	var selected string
	switch {
	case choice != "":
		// Принимаем и полный путь, и одно имя файла: в списке видно имя, и
		// набирать каталог целиком незачем.
		selected = choice
		if !strings.ContainsRune(choice, filepath.Separator) {
			selected = filepath.Join(m.BackupDir, choice)
		}
		if _, err := os.Stat(selected); err != nil {
			return fmt.Errorf("резервная копия %s не найдена", choice)
		}
	case len(entries) == 0:
		return fmt.Errorf("в %s нет ни одной резервной копии", m.BackupDir)
	default:
		fmt.Fprintf(m.Out, "Резервные копии в %s:\n\n", m.BackupDir)
		for i, e := range entries {
			fmt.Fprintf(m.Out, "  %2d) %s   %s, %s\n",
				i+1, e.when.Format("2006-01-02 15:04"), e.name, humanSize(e.size))
		}
		fmt.Fprintln(m.Out)
		if yes {
			// Выбирать за администратора можно только очевидное.
			selected = entries[0].path
			fmt.Fprintf(m.Out, "Беру самую свежую: %s\n", entries[0].name)
		} else {
			fmt.Fprintf(m.Out, "Какую восстановить? [1-%d, пусто — отмена] ", len(entries))
			line, _ := m.reader().ReadString('\n')
			line = strings.TrimSpace(line)
			if line == "" {
				fmt.Fprintln(m.Out, "Отменено.")
				return nil
			}
			n := 0
			if _, err := fmt.Sscanf(line, "%d", &n); err != nil || n < 1 || n > len(entries) {
				return fmt.Errorf("нет копии с номером %q", line)
			}
			selected = entries[n-1].path
		}
	}
	if err := validateBackupArchive(selected); err != nil {
		return fmt.Errorf("небезопасная или повреждённая резервная копия: %w", err)
	}

	if !yes && !m.confirm(fmt.Sprintf(
		"Текущая конфигурация, история и учётные записи будут заменены содержимым %s. Продолжить?",
		filepath.Base(selected))) {
		fmt.Fprintln(m.Out, "Отменено.")
		return nil
	}

	if err := m.stopDaemon(ctx); err != nil {
		return err
	}

	// Состояние до восстановления сохраняется всегда и без вопросов:
	// администратор согласился его заменить, а вернуться к нему после неудачного
	// восстановления будет неоткуда.
	safety, err := m.backup(ctx, "before-restore")
	if err != nil {
		_ = m.run(ctx, "systemctl", "start", "netosd")
		return err
	}

	// Каталоги очищаются перед распаковкой: tar кладёт файлы поверх, и без
	// уборки в восстановленной установке остались бы сегменты, правила и
	// пользователи, которых в копии нет.
	for _, path := range []string{m.StateDir, m.ConfigDir, m.LogDir} {
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("очистка %s: %w; состояние до восстановления: %s", path, err, safety)
		}
	}
	if err := m.run(ctx, "tar", "-C", string(filepath.Separator), "-xzf", selected); err != nil {
		return fmt.Errorf("распаковка %s: %w; состояние до восстановления: %s", selected, err, safety)
	}

	if err := m.run(ctx, "systemctl", "start", "netosd"); err != nil {
		return fmt.Errorf("запуск после восстановления: %w; состояние до восстановления: %s", err, safety)
	}
	fmt.Fprintf(m.Out, "Восстановлено из %s\n", filepath.Base(selected))
	fmt.Fprintf(m.Out, "Состояние до восстановления сохранено: %s\n", safety)
	fmt.Fprintln(m.Out, "Конфигурация из копии применена при запуске службы: netos status")
	return nil
}

const (
	maxBackupEntries = 100_000
	maxBackupBytes   = int64(2 << 30)
)

// validateBackupArchive ensures that root extraction cannot escape the three
// directories owned by netOS. Links and special files are intentionally
// rejected: they are unnecessary in a netOS backup and can redirect later tar
// entries to arbitrary paths.
func validateBackupArchive(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var entries int
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		entries++
		if entries > maxBackupEntries {
			return fmt.Errorf("слишком много файлов")
		}
		name := strings.TrimPrefix(h.Name, "./")
		// GNU tar (которым backup и создаётся) завершает имена каталогов
		// слешем. Для обычных файлов такой суффикс остаётся недопустимым.
		if h.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
		}
		clean := path.Clean(name)
		if clean == "." || clean != name || path.IsAbs(name) || strings.HasPrefix(clean, "../") || !backupPathAllowed(clean) {
			return fmt.Errorf("недопустимый путь %q", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			if h.Size < 0 || total > maxBackupBytes-h.Size {
				return fmt.Errorf("распакованный объём превышает предел")
			}
			total += h.Size
		case tar.TypeDir:
		default:
			return fmt.Errorf("недопустимый тип файла для %q", h.Name)
		}
	}
	return nil
}

func backupPathAllowed(name string) bool {
	for _, root := range []string{"var/lib/netos", "etc/netos", "var/log/netos"} {
		if name == root || strings.HasPrefix(name, root+"/") {
			return true
		}
	}
	return false
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f МБ", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d КБ", n/(1<<10))
	default:
		return fmt.Sprintf("%d Б", n)
	}
}

func (m *Manager) uninstall(ctx context.Context, yes, keepData bool) error {
	if !yes && !m.confirm("netOS и применённая им конфигурация будут удалены. Продолжить?") {
		fmt.Fprintln(m.Out, "Отменено.")
		return nil
	}
	if err := m.stopDaemon(ctx); err != nil {
		return err
	}
	if !keepData {
		backup, err := m.backup(ctx, "uninstall")
		if err != nil {
			_ = m.run(ctx, "systemctl", "start", "netosd")
			return err
		}
		fmt.Fprintf(m.Out, "Резервная копия: %s\n", backup)
	}

	// --no-reload у каждого disable ниже — не микрооптимизация. systemctl
	// сам просит systemd перечитать юниты после снятия симлинков, и на
	// удалении с десятком компонентов это десяток перезагрузок конфигурации
	// подряд. Каждая занимает около полусекунды и прогоняет все генераторы,
	// включая чужие сломанные: журнал заполняется их ошибками, а команда
	// заметно тормозит. Перечитывание нужно ровно одно — оно идёт ниже, после
	// удаления файлов юнитов.
	m.bestEffort(ctx, "systemctl", "disable", "--no-reload", "netosd")
	// Гасятся только те юниты компонентов, которые действительно заведены.
	// Компоненты включает администратор, и на машине с одной лишь панелью нет
	// ни одного из них: отсутствующий юнит — это достигнутая цель, а не сбой,
	// и systemctl ругался бы на каждый пятью строками подряд.
	for _, unit := range []string{"netos-dnsmasq.service", "netos-isc-dhcp.service", "netos-kea-dhcp4.service", "netos-unbound.service", "netos-dnsproxy.service"} {
		if _, err := os.Stat(m.sys("/etc/systemd/system/" + unit)); err != nil {
			continue
		}
		m.bestEffort(ctx, "systemctl", "disable", "--no-reload", "--now", unit)
	}
	// Юниты, которых по одному на интерфейс или аплинк, ищем по маске: их
	// имена зависят от конфигурации, и списком их не перечислить.
	for _, pattern := range []string{
		"netos-dhcp-*.service", "netos-pppoe-*.service", "netos-l2tp-*.service",
		"netos-openconnect-ch*.service", "netos-xray-ch*.service",
		"netos-xray-srv*.service",
		"netos-hostapd-*.service",
		"netos-ocserv-srv*.service",
		"netos-strongswan.service",
	} {
		units, _ := filepath.Glob(m.sys("/etc/systemd/system/" + pattern))
		for _, unit := range units {
			m.bestEffort(ctx, "systemctl", "disable", "--no-reload", "--now", filepath.Base(unit))
			_ = os.Remove(unit)
		}
	}

	// netOS владеет полными таблицами firewall, поэтому при удалении оставляет
	// систему с разрешающими пустыми таблицами, а не с последним DROP ruleset.
	clear4 := "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n" +
		"*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n" +
		"*mangle\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n"
	clear6 := "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
	m.bestEffortInput(ctx, clear4, "iptables-restore")
	m.bestEffortInput(ctx, clear6, "ip6tables-restore")
	// Дефолтные маршруты запоминаются до очистки: следующая строка сносит в том
	// числе маршрут аплинка, и без запаса вернуть его будет неоткуда.
	savedRoutes := m.captureDefaultRoutes(ctx)
	m.bestEffort(ctx, "ip", "-4", "route", "flush", "table", "all", "proto", "static")
	m.bestEffort(ctx, "ip", "-4", "route", "flush", "table", "all", "proto", "201")
	m.removePolicyRules(ctx)
	m.removeVirtualInterfaces(ctx)
	// Параметры ядра возвращаются записью в /proc/sys, а не командой sysctl:
	// она живёт в пакете procps, которого на минимальной установке Debian нет,
	// и удаление оставило бы машину с выключенным IPv6 и включённым
	// форвардингом.
	for key, value := range map[string]string{
		"net.ipv4.ip_forward":                "0",
		"net.ipv6.conf.all.disable_ipv6":     "0",
		"net.ipv6.conf.default.disable_ipv6": "0",
		"net.ipv6.conf.all.accept_ra":        "1",
		"net.ipv6.conf.default.accept_ra":    "1",
		"net.ipv6.conf.all.autoconf":         "1",
		"net.ipv6.conf.default.autoconf":     "1",
	} {
		path := filepath.Join(m.sys("/proc/sys"), filepath.Join(strings.Split(key, ".")...))
		_ = os.WriteFile(path, []byte(value), 0o644)
	}

	// Резолвер роутера возвращается системе до удаления состояния: чем был
	// /etc/resolv.conf до netOS, помнит файл в StateDir, и после его удаления
	// восстанавливать будет неоткуда.
	if resolvedWanted, err := services.RestoreSystemResolverFiles(m.Root); err != nil {
		fmt.Fprintf(m.Err, "Предупреждение: резолвер системы не восстановлен: %v\n", err)
	} else if resolvedWanted {
		m.quiet(ctx, "systemctl", "enable", "--now", "systemd-resolved.service")
	}

	// Режим управления сетью определяется до удаления файлов: после него
	// понять, кому возвращать интерфейсы, будет уже нельзя.
	ifupdownMode := false
	if _, err := os.Stat(m.sys("/etc/network/interfaces.d/netos.conf")); err == nil {
		ifupdownMode = true
	}

	for _, path := range []string{
		m.Unit,
		m.sys("/etc/systemd/system/netos-dnsmasq.service"),
		m.sys("/etc/systemd/system/netos-isc-dhcp.service"),
		m.sys("/etc/systemd/system/netos-kea-dhcp4.service"),
		m.sys("/etc/sysctl.d/99-netos.conf"), m.sys("/etc/sysctl.d/99-netos-ipv6.conf"),
		m.sys("/etc/modules-load.d/netos.conf"),
		m.sys("/etc/iproute2/rt_tables.d/netos.conf"), m.sys("/etc/iproute2/rt_protos.d/netos.conf"),
		m.sys("/etc/iproute2/rt_tables.d/netos-channels.conf"),
		m.sys("/etc/apt/apt.conf.d/99netos"),
		m.sys("/etc/bash_completion.d/netos"),
		// Персистентная конфигурация сети: без неё удаление netOS оставило бы
		// машину с описанием сегментов, которых больше никто не создаёт.
		m.sys("/etc/network/interfaces.d/netos.conf"),
		m.sys("/etc/systemd/system/systemd-networkd-wait-online.service.d/99-netos.conf"),
		// Отстранение NetworkManager снимается вместе с netOS: иначе
		// интерфейсы остались бы ничьими и после перезагрузки машина не
		// поднялась бы в сеть.
		m.sys("/etc/NetworkManager/conf.d/99-netos.conf"),
	} {
		_ = os.Remove(path)
	}
	networkd, _ := filepath.Glob(m.sys("/etc/systemd/network/05-netos-*"))
	var links []string
	for _, path := range networkd {
		name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "05-netos-"), ".network")
		if name != "" {
			links = append(links, name)
		}
		_ = os.Remove(path)
	}
	if !keepData {
		for _, path := range []string{m.StateDir, m.ConfigDir, m.LogDir} {
			if err := os.RemoveAll(path); err != nil {
				return err
			}
		}
	}
	_ = os.Remove(m.Binary)
	_ = os.Remove(m.CLI)
	m.bestEffort(ctx, "systemctl", "daemon-reload")
	// Демоны, которых netOS погасил ради единоличного управления, возвращаются
	// вместе с системой: удаление обязано оставлять машину такой, какой она
	// была до установки.
	for _, unit := range []string{"tuned.service"} {
		m.quiet(ctx, "systemctl", "enable", "--now", unit)
	}
	// NetworkManager должен узнать, что интерфейсы снова его.
	m.quiet(ctx, "systemctl", "reload", "NetworkManager.service")
	m.restoreNetworking(ctx, links, ifupdownMode, savedRoutes)
	fmt.Fprintln(m.Out, "netOS удалён. Установленные через apt компоненты оставлены в системе.")
	return nil
}

func (m *Manager) backup(ctx context.Context, reason string) (string, error) {
	if err := os.MkdirAll(m.BackupDir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(m.BackupDir, fmt.Sprintf("netos-%s-%s.tar.gz", reason, m.Now().Format("20060102-150405")))
	var sources []string
	for _, source := range []string{m.StateDir, m.ConfigDir, m.LogDir} {
		if _, err := os.Stat(source); err == nil {
			sources = append(sources, strings.TrimPrefix(filepath.Clean(source), string(filepath.Separator)))
		}
	}
	if len(sources) == 0 {
		return path, nil
	}
	args := append([]string{"-C", string(filepath.Separator), "-czf", path}, sources...)
	if err := m.run(ctx, "tar", args...); err != nil {
		return "", fmt.Errorf("резервное копирование: %w", err)
	}
	// Архив содержит базу с хэшами паролей, bearer-сессиями и секретами
	// сетей. Права каталога уже 0700, но сам файл также должен оставаться
	// закрытым при переносе или ошибочном изменении прав родителя.
	if err := os.Chmod(path, 0o600); err != nil {
		return "", fmt.Errorf("права резервной копии: %w", err)
	}
	return path, nil
}

func (m *Manager) backupNow(ctx context.Context) error {
	if err := m.stopDaemon(ctx); err != nil {
		return err
	}
	path, err := m.backup(ctx, "backup")
	startErr := m.run(ctx, "systemctl", "start", "netosd")
	if err != nil {
		return err
	}
	if startErr != nil {
		return fmt.Errorf("резервная копия создана в %s, но служба не запустилась: %w", path, startErr)
	}
	fmt.Fprintf(m.Out, "Резервная копия создана: %s\n", path)
	return nil
}

// defaultRoute описывает дефолтный маршрут в объёме, которого хватает, чтобы
// вернуть его на место.
type defaultRoute struct {
	via string
	dev string
}

// captureDefaultRoutes запоминает дефолтные маршруты до того, как удаление их
// снесёт.
func (m *Manager) captureDefaultRoutes(ctx context.Context) []defaultRoute {
	out, err := m.Output(ctx, "ip", "-4", "route", "show", "default")
	if err != nil {
		return nil
	}
	var routes []defaultRoute
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		var r defaultRoute
		for i := 0; i+1 < len(fields); i++ {
			switch fields[i] {
			case "via":
				r.via = fields[i+1]
			case "dev":
				r.dev = fields[i+1]
			}
		}
		if r.dev != "" {
			routes = append(routes, r)
		}
	}
	return routes
}

// restoreNetworking возвращает интерфейсы штатному менеджеру сети.
//
// Одного удаления файлов мало. Маршруты netOS сняты вместе с proto 201, но
// systemd-networkd продолжает держать в памяти прежнюю конфигурацию линка и
// адресацию заново не запускает: машина остаётся с адресом, но без пути
// наружу. На роутере, который админят удалённо, это потеря доступа до
// перезагрузки — ровно то, ради чего удаление и запускали, только без связи.
//
// Попытки идут молча: на машине с ifupdown нет networkctl, на машине с
// networkd нет networking.service, и сообщать о таких неудачах нечего.
// Значение имеет один факт — появился дефолтный маршрут или нет.
func (m *Manager) restoreNetworking(ctx context.Context, links []string, ifupdownMode bool, saved []defaultRoute) {
	m.quiet(ctx, "networkctl", "reload")
	for _, link := range links {
		// Виртуальных интерфейсов netOS к этому моменту уже нет, и
		// reconfigure для них означал бы только шум в выводе.
		if _, err := os.Stat(m.sys("/sys/class/net/" + link)); err != nil {
			continue
		}
		m.quiet(ctx, "networkctl", "reconfigure", link)
	}
	if ifupdownMode {
		m.quiet(ctx, "systemctl", "restart", "networking")
	}
	if m.waitDefaultRoute(ctx, 20) {
		return
	}

	// Штатный менеджер маршрут не вернул. Ставим обратно тот, что был до
	// удаления: маршрут чужого происхождения лучше, чем машина без связи.
	for _, r := range saved {
		if r.via != "" {
			m.quiet(ctx, "ip", "-4", "route", "add", "default", "via", r.via, "dev", r.dev)
		} else {
			m.quiet(ctx, "ip", "-4", "route", "add", "default", "dev", r.dev)
		}
	}
	if len(saved) > 0 && m.waitDefaultRoute(ctx, 3) {
		fmt.Fprintln(m.Out, "Дефолтный маршрут восстановлен вручную: штатный менеджер сети его не вернул.")
		return
	}
	fmt.Fprintln(m.Err, "Предупреждение: машина осталась без дефолтного маршрута. Проверьте сеть до перезагрузки.")
}

// waitDefaultRoute ждёт появления дефолтного маршрута, опрашивая таблицу раз в
// секунду. DHCP-аренда приходит не мгновенно, а проверять сразу после
// reconfigure означало бы объявить восстановление неудачным раньше времени.
func (m *Manager) waitDefaultRoute(ctx context.Context, attempts int) bool {
	for i := 0; ; i++ {
		out, err := m.Output(ctx, "ip", "-4", "route", "show", "default")
		if err == nil && strings.TrimSpace(out) != "" {
			return true
		}
		if i >= attempts {
			return false
		}
		m.Sleep(time.Second)
	}
}

// quiet выполняет попытку восстановления, о неудаче которой сообщать нечего.
//
// Гасится и вывод самой команды: systemctl честно пишет «Unit
// NetworkManager.service not found» на машине, где его нет, и это выглядело бы
// сбоем удаления, хотя ничего не произошло.
func (m *Manager) quiet(ctx context.Context, name string, args ...string) {
	_ = m.Run(ctx, command{name: name, args: args, silent: true})
}

func (m *Manager) removePolicyRules(ctx context.Context) {
	out, err := m.Output(ctx, "ip", "-4", "rule", "show")
	if err != nil {
		fmt.Fprintf(m.Err, "Предупреждение: чтение policy rules: %v\n", err)
		return
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var priority int
		if _, err := fmt.Sscanf(strings.TrimSuffix(fields[0], ":"), "%d", &priority); err != nil {
			continue
		}
		if priority >= 20000 && priority <= 29999 {
			m.bestEffort(ctx, "ip", "-4", "rule", "del", "priority", fmt.Sprint(priority))
		}
	}
}

func (m *Manager) removeVirtualInterfaces(ctx context.Context) {
	entries, err := os.ReadDir(m.sys("/sys/class/net"))
	if err != nil {
		fmt.Fprintf(m.Err, "Предупреждение: чтение интерфейсов: %v\n", err)
		return
	}
	prefixes := []string{"br-", "vl-", "bond-", "d-", "wg-ch", "tun-ch", "wg-srv", "xfrm-ch", "xfrm-srv"}
	for _, entry := range entries {
		for _, prefix := range prefixes {
			if strings.HasPrefix(entry.Name(), prefix) {
				m.bestEffort(ctx, "ip", "link", "delete", entry.Name())
				break
			}
		}
	}
}

// reader отдаёт общий буферизованный ввод, создавая его при первом вопросе.
func (m *Manager) reader() *bufio.Reader {
	if m.in == nil {
		m.in = bufio.NewReader(m.In)
	}
	return m.in
}

func (m *Manager) confirm(question string) bool {
	fmt.Fprintf(m.Out, "%s [y/N] ", question)
	line, _ := m.reader().ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes", "д", "да":
		return true
	default:
		return false
	}
}

// stopDaemon останавливает службу. Отсутствующий или уже остановленный юнит —
// не ошибка: удаление и сброс должны доводиться до конца и на машине, где
// предыдущая попытка оборвалась на середине (systemctl stop отдаёт код 5 на
// незагруженный юнит, и без этой проверки uninstall падал на первом же шаге).
func (m *Manager) stopDaemon(ctx context.Context) error {
	stopErr := m.run(ctx, "systemctl", "stop", "netosd")
	if stopErr == nil {
		return nil
	}
	state, _ := m.Output(ctx, "systemctl", "is-active", "netosd")
	switch strings.TrimSpace(state) {
	case "inactive", "failed", "unknown", "":
		return nil
	}
	return stopErr
}

func (m *Manager) requireRoot() error {
	if m.EUID() != 0 {
		return fmt.Errorf("нужны права root; запустите команду через sudo")
	}
	return nil
}

func (m *Manager) run(ctx context.Context, name string, args ...string) error {
	return m.Run(ctx, command{name: name, args: args})
}

func (m *Manager) runEnv(ctx context.Context, env []string, name string, args ...string) error {
	return m.Run(ctx, command{name: name, args: args, env: env})
}

func (m *Manager) bestEffort(ctx context.Context, name string, args ...string) {
	if err := m.run(ctx, name, args...); err != nil {
		fmt.Fprintf(m.Err, "Предупреждение: %s: %v\n", name, err)
	}
}

func (m *Manager) bestEffortInput(ctx context.Context, input, name string, args ...string) {
	if err := m.Run(ctx, command{name: name, args: args, stdin: input}); err != nil {
		fmt.Fprintf(m.Err, "Предупреждение: %s: %v\n", name, err)
	}
}

func (m *Manager) runOS(ctx context.Context, spec command) error {
	cmd := exec.CommandContext(ctx, spec.name, spec.args...)
	cmd.Stdout, cmd.Stderr = m.Out, m.Err
	if spec.silent {
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	}
	if spec.stdin != "" {
		cmd.Stdin = strings.NewReader(spec.stdin)
	} else {
		cmd.Stdin = m.In
	}
	cmd.Env = append(os.Environ(), spec.env...)
	return cmd.Run()
}

func (m *Manager) outputOS(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stderr = m.Err
	out, err := cmd.Output()
	return string(out), err
}

func positionalVersion(args []string) (string, error) {
	if len(args) > 1 {
		return "", fmt.Errorf("ожидалась не более чем одна версия")
	}
	if len(args) == 0 {
		return "", nil
	}
	if strings.HasPrefix(args[0], "-") || !validVersion(args[0]) {
		return "", fmt.Errorf("некорректная версия %q", args[0])
	}
	return args[0], nil
}

func validVersion(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || strings.ContainsRune("._+-", r) {
			continue
		}
		return false
	}
	return true
}

// extractFlags отделяет перечисленные флаги от позиционных аргументов и
// сообщает, встретился ли хоть один из них. Нужен там, где флаг может стоять
// и до, и после значения: "netos update --force v0.06" и "netos update v0.06
// --force" — одна и та же команда.
func extractFlags(args []string, flags ...string) ([]string, bool) {
	var rest []string
	found := false
	for _, arg := range args {
		if contains(flags, arg) {
			found = true
			continue
		}
		rest = append(rest, arg)
	}
	return rest, found
}

func onlyFlags(args []string, allowed ...string) error {
	for _, arg := range args {
		if !contains(allowed, arg) {
			return fmt.Errorf("неизвестный параметр %q", arg)
		}
	}
	return nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func displayVersion(version string) string {
	if version == "" {
		return "dev"
	}
	return version
}
