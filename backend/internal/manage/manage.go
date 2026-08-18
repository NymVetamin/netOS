// Package manage реализует пользовательскую команду netos. Демон остаётся
// внутренним процессом netosd, а повседневное управление идёт через этот CLI.
package manage

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const installerURL = "https://raw.githubusercontent.com/NymVetamin/netOS/master/install.sh"

// renderableArtifacts перечисляет то, что умеет печатать netosd -render.
// Список продублирован здесь намеренно: CLI обязан отказать до запуска демона,
// а не показывать пользователю его внутреннюю ошибку.
var renderableArtifacts = []string{"iptables", "dnsmasq", "unbound", "dnsproxy", "network", "config"}

type command struct {
	name  string
	args  []string
	env   []string
	stdin string
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

	// Root подставляется перед всеми системными путями. В работе он пуст, а в
	// тестах указывает на временный каталог: иначе прогон тестов удаления под
	// root снёс бы установленный netOS на самой машине сборки.
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
		Version: version, EUID: effectiveUID, Now: time.Now,
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
		version, err := positionalVersion(args[1:])
		if err != nil {
			return err
		}
		return m.install(ctx, version)
	case "reset":
		if err := m.requireRoot(); err != nil {
			return err
		}
		if err := onlyFlags(args[1:], "--yes", "-y"); err != nil {
			return err
		}
		return m.reset(ctx, contains(args[1:], "--yes") || contains(args[1:], "-y"))
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
  netos update [версия]        обновить до latest или указанной версии
  netos reinstall [версия]     то же, что update
  netos reset [-y|--yes]       сбросить настройки и пользователей к заводским
  netos uninstall [--keep-data] [-y|--yes]
                               удалить netOS (по умолчанию с резервной копией)
  netos backup                 создать резервную копию
  netos start|stop|restart     управление службой
  netos plan                   показать план активной конфигурации
  netos render <артефакт>      вывести сгенерированный конфиг:
                               iptables, dnsmasq, isc-dhcp, kea-dhcp4, unbound, dnsproxy,
                               network, config
  netos version                версия netOS

update и reinstall сохраняют конфигурацию, пользователей и сертификаты.`)
}

func (m *Manager) install(ctx context.Context, version string) error {
	tmp, err := os.CreateTemp("", "netos-install-*.sh")
	if err != nil {
		return err
	}
	path := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(path)

	fmt.Fprintln(m.Out, "Загружаю установщик netOS…")
	if err := m.run(ctx, "curl", "-4", "-fsSL", "--retry", "3", "-o", path, installerURL); err != nil {
		return fmt.Errorf("загрузка установщика: %w", err)
	}
	var env []string
	if version != "" {
		env = append(env, "NETOS_VERSION="+version)
	}
	if _, err := m.Output(ctx, "curl", "-4", "-fsSIL", "--retry", "2", releaseURL(version)); err != nil {
		fmt.Fprintln(m.Out, "Готового релиза для этой версии нет — собираю из исходников.")
		env = append(env, "NETOS_FROM_SOURCE=1")
	}
	return m.runEnv(ctx, env, "bash", path)
}

func releaseURL(version string) string {
	if version == "" || version == "latest" {
		return fmt.Sprintf("https://github.com/NymVetamin/netOS/releases/latest/download/netosd-linux-%s", runtime.GOARCH)
	}
	return fmt.Sprintf("https://github.com/NymVetamin/netOS/releases/download/%s/netosd-linux-%s", version, runtime.GOARCH)
}

func (m *Manager) reset(ctx context.Context, yes bool) error {
	if !yes && !m.confirm("Сброс удалить все настройки, историю и пользователей. Продолжить?") {
		fmt.Fprintln(m.Out, "Отменено.")
		return nil
	}
	if err := m.stopDaemon(ctx); err != nil {
		return err
	}
	backup, err := m.backup(ctx, "reset")
	if err != nil {
		_ = m.run(ctx, "systemctl", "start", "netosd")
		return err
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
		return fmt.Errorf("запуск после сброса: %w; резервная копия: %s", err, backup)
	}
	fmt.Fprintf(m.Out, "netOS сброшен. Резервная копия: %s\n", backup)
	credentials := filepath.Join(m.StateDir, "initial-credentials")
	for i := 0; i < 80; i++ {
		if info, err := os.Stat(credentials); err == nil && info.Size() > 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if _, err := os.Stat(credentials); err == nil {
		fmt.Fprintf(m.Out, "Новые данные входа: %s\n", credentials)
	} else {
		fmt.Fprintf(m.Err, "Новые данные входа ещё создаются; проверьте: netos logs -f\n")
	}
	return nil
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

	m.bestEffort(ctx, "systemctl", "disable", "netosd")
	for _, unit := range []string{"netos-dnsmasq.service", "netos-isc-dhcp.service", "netos-kea-dhcp4.service", "netos-unbound.service", "netos-dnsproxy.service"} {
		m.bestEffort(ctx, "systemctl", "disable", "--now", unit)
	}
	// Юниты, которых по одному на интерфейс или аплинк, ищем по маске: их
	// имена зависят от конфигурации, и списком их не перечислить.
	for _, pattern := range []string{"netos-dhcp-*.service", "netos-pppoe-*.service"} {
		units, _ := filepath.Glob(m.sys("/etc/systemd/system/" + pattern))
		for _, unit := range units {
			m.bestEffort(ctx, "systemctl", "disable", "--now", filepath.Base(unit))
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
	m.bestEffort(ctx, "ip", "-4", "route", "flush", "table", "all", "proto", "static")
	m.bestEffort(ctx, "ip", "-4", "route", "flush", "table", "all", "proto", "201")
	m.removePolicyRules(ctx)
	m.removeVirtualInterfaces(ctx)
	m.bestEffort(ctx, "sysctl", "-q", "-w", "net.ipv4.ip_forward=0")
	m.bestEffort(ctx, "sysctl", "-q", "-w", "net.ipv6.conf.all.disable_ipv6=0")
	m.bestEffort(ctx, "sysctl", "-q", "-w", "net.ipv6.conf.default.disable_ipv6=0")
	m.bestEffort(ctx, "sysctl", "-q", "-w", "net.ipv6.conf.all.accept_ra=1")
	m.bestEffort(ctx, "sysctl", "-q", "-w", "net.ipv6.conf.default.accept_ra=1")
	m.bestEffort(ctx, "sysctl", "-q", "-w", "net.ipv6.conf.all.autoconf=1")
	m.bestEffort(ctx, "sysctl", "-q", "-w", "net.ipv6.conf.default.autoconf=1")

	for _, path := range []string{
		m.Unit,
		m.sys("/etc/systemd/system/netos-dnsmasq.service"),
		m.sys("/etc/systemd/system/netos-isc-dhcp.service"),
		m.sys("/etc/systemd/system/netos-kea-dhcp4.service"),
		m.sys("/etc/sysctl.d/99-netos.conf"), m.sys("/etc/sysctl.d/99-netos-ipv6.conf"),
		m.sys("/etc/iproute2/rt_tables.d/netos.conf"), m.sys("/etc/iproute2/rt_protos.d/netos.conf"),
		m.sys("/etc/apt/apt.conf.d/99netos"),
		// Персистентная конфигурация сети: без неё удаление netOS оставило бы
		// машину с описанием сегментов, которых больше никто не создаёт.
		m.sys("/etc/network/interfaces.d/netos.conf"),
	} {
		_ = os.Remove(path)
	}
	networkd, _ := filepath.Glob(m.sys("/etc/systemd/network/05-netos-*"))
	for _, path := range networkd {
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
	prefixes := []string{"br-", "vl-", "bond-", "d-", "wg-ch", "tun-ch", "wg-srv"}
	for _, entry := range entries {
		for _, prefix := range prefixes {
			if strings.HasPrefix(entry.Name(), prefix) {
				m.bestEffort(ctx, "ip", "link", "delete", entry.Name())
				break
			}
		}
	}
}

func (m *Manager) confirm(question string) bool {
	fmt.Fprintf(m.Out, "%s [y/N] ", question)
	line, _ := bufio.NewReader(m.In).ReadString('\n')
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
