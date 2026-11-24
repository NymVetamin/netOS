package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// SystemResolver владеет резолвером самого роутера — файлом /etc/resolv.conf.
//
// Резолвер выбирают в панели, и выбирают его для всей машины, а не только для
// клиентов. Пока /etc/resolv.conf указывает на systemd-resolved, роутер ходит
// за именами мимо выбранного резолвера: apt, проверки живости каналов,
// разрешение адресов VPN-эндпоинтов и обновления идут в обход шифрования,
// фильтров и локальной зоны. Администратор при этом видит в панели включённый
// DoT и считает, что им пользуется вся машина.
//
// Поэтому netOS забирает /etc/resolv.conf себе, а systemd-resolved гасит.
// Исходное состояние файла запоминается: удаление netOS обязано вернуть
// машину такой, какой она была.
type SystemResolver struct {
	Runner  system.Runner
	Systemd *system.Systemd
	// Root подставляется в тестах, чтобы не трогать /etc настоящей машины.
	Root string
}

func NewSystemResolver(r system.Runner) *SystemResolver {
	return &SystemResolver{Runner: r, Systemd: system.NewSystemd(r), Root: systemResolverRoot}
}

var systemResolverRoot string

const (
	resolvConfPath = "/etc/resolv.conf"
	// resolvStatePath помнит, чем был /etc/resolv.conf до того, как netOS его
	// забрал: сам файл вернуть иначе будет неоткуда.
	resolvStatePath = "/var/lib/netos/resolv-conf.state"
	resolvedUnit    = "systemd-resolved.service"
	netOSResolvMark = "# Сгенерировано netOS."
)

// resolvState — исходное состояние резолвера машины.
type resolvState struct {
	// Kind: symlink, file или absent.
	Kind string `json:"kind"`
	// Target — цель симлинка, Content — содержимое обычного файла.
	Target  string `json:"target,omitempty"`
	Content string `json:"content,omitempty"`
	// Older versions and management recovery use the combined active-or-enabled flag.
	ResolvedEnabled bool   `json:"resolved_enabled"`
	ResolvedActive  bool   `json:"resolved_active,omitempty"`
	UnitFileState   string `json:"resolved_unit_file_state,omitempty"`
}

func (u *SystemResolver) path(p string) string {
	if u.Root == "" {
		return p
	}
	return filepath.Join(u.Root, p)
}

// Needed сообщает, может ли роутер пользоваться собственным резолвером.
//
// Порт, отличный от 53, означает, что не может: в /etc/resolv.conf порт
// указать нельзя, и ни одна системная утилита туда не пойдёт. Тогда файл
// остаётся системе, а валидатор объясняет это администратору.
func (u *SystemResolver) Needed(cfg *config.Config) bool {
	return cfg.DNS.Enabled && cfg.DNS.Port == 53
}

// Render собирает /etc/resolv.conf.
func (u *SystemResolver) Render(cfg *config.Config) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("# Сгенерировано netOS. Правки будут перезаписаны при следующем применении.")
	w("# Резолвер роутера — тот же, что выбран в панели (%s). Второго пути к", cfg.DNS.Provider)
	w("# именам у машины нет: он обошёл бы шифрование, фильтры и локальную зону.")
	w("nameserver 127.0.0.1")
	if cfg.DNS.LocalDomain != "" {
		w("search %s", cfg.DNS.LocalDomain)
	}
	w("options edns0")
	return b.String()
}

func (u *SystemResolver) Apply(ctx context.Context, cfg *config.Config) error {
	if !u.Needed(cfg) {
		return u.Release(ctx)
	}
	if err := u.capture(ctx); err != nil {
		return err
	}
	// systemd-resolved держит собственный сервер на 127.0.0.53 и переписывает
	// resolv.conf под себя. Гасится он после того, как запомнено его исходное
	// состояние, и только здесь — то есть после того, как выбранный резолвер
	// уже поднят: иначе машина осталась бы без имён посреди применения.
	// Runtime enablement has separate links under /run/systemd/system.
	mode, _ := u.Runner.Run(ctx, "systemctl", "is-enabled", resolvedUnit)
	if strings.TrimSpace(mode) == "enabled-runtime" {
		if _, err := u.Runner.Run(ctx, "systemctl", "disable", "--runtime", resolvedUnit); err != nil {
			return err
		}
	}
	if err := u.Systemd.Disable(ctx, resolvedUnit); err != nil {
		return fmt.Errorf("остановка %s: %w", resolvedUnit, err)
	}

	content := []byte(u.Render(cfg))
	if !u.changed(content) {
		return nil
	}
	// WriteFileAtomic заканчивается rename: он заменяет и обычный файл, и
	// симлинк на systemd-resolved, причём целиком, без промежуточного
	// состояния, в котором у машины нет резолвера вовсе.
	return system.WriteFileAtomic(u.path(resolvConfPath), content, 0o644)
}

// changed сообщает, отличается ли живой /etc/resolv.conf от нужного.
// Симлинк считается отличающимся всегда: читать его целевой файл бессмысленно,
// заменить его всё равно придётся.
func (u *SystemResolver) changed(content []byte) bool {
	path := u.path(resolvConfPath)
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	return string(current) != string(content)
}

// capture запоминает исходное состояние резолвера — один раз, при первом
// захвате. Повторный вызов ничего не переписывает: иначе после первого же
// применения в памяти оказался бы наш собственный файл, и возвращать при
// удалении было бы нечего.
func (u *SystemResolver) capture(ctx context.Context) error {
	statePath := u.path(resolvStatePath)
	if _, err := os.Stat(statePath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}

	var state resolvState
	props, err := readDNSUnitProperties(ctx, u.Runner, resolvedUnit)
	loadState, activeState := props["LoadState"], props["ActiveState"]
	state.UnitFileState = props["UnitFileState"]
	if loadState != "not-found" {
		if err != nil {
			return fmt.Errorf("чтение состояния %s: %w", resolvedUnit, err)
		}
		if loadState == "" || activeState == "" || state.UnitFileState == "" {
			return fmt.Errorf("неполное состояние %s", resolvedUnit)
		}
	}
	state.ResolvedActive = activeState == "active" || activeState == "activating" || activeState == "reloading"
	state.ResolvedEnabled = state.ResolvedActive
	switch state.UnitFileState {
	case "enabled", "enabled-runtime", "alias", "indirect":
		state.ResolvedEnabled = true
	}
	path := u.path(resolvConfPath)
	switch info, err := os.Lstat(path); {
	case err != nil && os.IsNotExist(err):
		state.Kind = "absent"
	case err != nil:
		return err
	case info.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(path)
		if err != nil {
			return err
		}
		// Symlink targets are persisted as Linux paths because this state belongs
		// to a Linux appliance. ToSlash also keeps cross-platform tests honest.
		state.Kind, state.Target = "symlink", filepath.ToSlash(target)
	default:
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		state.Kind, state.Content = "file", string(content)
	}

	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return system.WriteFileAtomic(statePath, data, 0o600)
}

// Release returns the resolver file and the captured service state together.
func (u *SystemResolver) Release(ctx context.Context) error {
	_, err := restoreSystemResolverFiles(u.Root, func(state resolvState) error {
		if !state.ResolvedEnabled {
			return nil
		}
		args := []string{"enable"}
		switch state.UnitFileState {
		case "": // Legacy state only records active OR enabled.
			args = append(args, "--now")
		case "enabled", "enabled-runtime":
			if state.UnitFileState == "enabled-runtime" {
				args = append(args, "--runtime")
			}
			if state.ResolvedActive {
				args = append(args, "--now")
			}
		default:
			if !state.ResolvedActive {
				return nil
			}
			args = []string{"start"}
		}
		_, err := u.Runner.Run(ctx, "systemctl", append(args, resolvedUnit)...)
		if err != nil {
			return fmt.Errorf("восстановление %s: %w", resolvedUnit, err)
		}
		return nil
	})
	return err
}

func (u *SystemResolver) Health(ctx context.Context, cfg *config.Config) error {
	path := u.path(resolvConfPath)
	statePath := u.path(resolvStatePath)
	if u.Needed(cfg) {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("проверка %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s остался символической ссылкой", path)
		}
		if err := managedFileHealth(path, []byte(u.Render(cfg)), 0o644); err != nil {
			return err
		}
		if _, err := os.Stat(statePath); err != nil {
			return fmt.Errorf("снимок исходного resolver: %w", err)
		}
		if u.Systemd.IsActive(ctx, resolvedUnit) || !u.Systemd.IsDisabled(ctx, resolvedUnit) {
			return fmt.Errorf("%s продолжает управлять resolver", resolvedUnit)
		}
		return nil
	}
	if _, err := os.Stat(statePath); err == nil {
		return fmt.Errorf("после release остался state %s", statePath)
	} else if !os.IsNotExist(err) {
		return err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.HasPrefix(string(content), netOSResolvMark) {
			return fmt.Errorf("netOS всё ещё владеет %s", path)
		}
	}
	return nil
}

// RestoreSystemResolverFiles возвращает /etc/resolv.conf в то состояние, в
// котором его застал netOS, и сообщает, работал ли до него systemd-resolved.
//
// Запуск команд оставлен вызывающему: удаление netOS выполняет их своим
// способом и со своими правилами про Root, а файл, который netOS забрал, и
// файл, который он возвращает, обязаны остаться одним и тем же — поэтому
// логика живёт здесь, рядом с захватом, а не переписывается в уборке заново.
func RestoreSystemResolverFiles(root string) (bool, error) {
	return restoreSystemResolverFiles(root, nil)
}

func restoreSystemResolverFiles(root string, restoreService func(resolvState) error) (bool, error) {
	at := func(p string) string {
		if root == "" {
			return p
		}
		return filepath.Join(root, p)
	}

	statePath := at(resolvStatePath)
	data, err := os.ReadFile(statePath)
	if os.IsNotExist(err) {
		// Старые версии netOS не всегда сохраняли state. Не трогаем произвольный
		// системный файл, но и не оставляем машину с мёртвым 127.0.0.1 после
		// удаления, если файл безошибочно узнаётся как сгенерированный netOS.
		return false, recoverSystemResolverWithoutState(at)
	} else if err != nil {
		return false, err
	}
	var state resolvState
	if err := json.Unmarshal(data, &state); err != nil {
		return false, err
	}

	path := at(resolvConfPath)
	switch state.Kind {
	case "symlink":
		if err := system.RestoreSymlinkAtomic(path, state.Target); err != nil {
			return false, err
		}
	case "file":
		if err := system.WriteFileAtomic(path, []byte(state.Content), 0o644); err != nil {
			return false, err
		}
	case "absent":
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return false, err
		}
	default:
		return false, fmt.Errorf("неизвестный kind resolver state %q", state.Kind)
	}
	if restoreService != nil {
		if err := restoreService(state); err != nil {
			return false, err
		}
	}
	if err := os.Remove(statePath); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	return state.ResolvedEnabled, nil
}

// recoverSystemResolverWithoutState чинит только legacy-состояние, в котором
// netOS владеет /etc/resolv.conf, а снимка исходного файла уже нет. Источники
// перечислены от наиболее близких к готовому системному resolv.conf до DHCP
// leases systemd-networkd. Если система не оставила ни одного адреса, лучше
// завершить удаление с явной ошибкой, чем незаметно подменять локальный DNS
// публичным сервером, который может быть недоступен или запрещён политикой.
func recoverSystemResolverWithoutState(at func(string) string) error {
	path := at(resolvConfPath)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(current), netOSResolvMark) {
		return nil
	}

	for _, candidate := range []string{
		"/run/systemd/resolve/resolv.conf",
		"/run/NetworkManager/no-stub-resolv.conf",
		"/run/NetworkManager/resolv.conf",
		"/run/resolvconf/resolv.conf",
	} {
		content, readErr := os.ReadFile(at(candidate))
		if readErr != nil {
			if os.IsNotExist(readErr) {
				continue
			}
			return readErr
		}
		if usableResolverContent(content) {
			return system.WriteFileAtomic(path, content, 0o644)
		}
	}

	leases, err := filepath.Glob(at("/run/systemd/netif/leases/*"))
	if err != nil {
		return err
	}
	var servers []string
	seen := map[string]bool{}
	for _, lease := range leases {
		content, readErr := os.ReadFile(lease)
		if readErr != nil {
			continue
		}
		for _, line := range strings.Split(string(content), "\n") {
			key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok || key != "DNS" {
				continue
			}
			value = strings.Trim(value, "\"'")
			for _, field := range strings.Fields(value) {
				ip := net.ParseIP(strings.Trim(field, "[]"))
				if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || seen[ip.String()] {
					continue
				}
				seen[ip.String()] = true
				servers = append(servers, ip.String())
			}
		}
	}
	if len(servers) == 0 {
		return fmt.Errorf("исходное состояние %s утрачено, системные DNS-серверы не найдены", resolvConfPath)
	}

	var restored strings.Builder
	restored.WriteString("# Восстановлено при удалении netOS из DNS, полученных системой.\n")
	for _, server := range servers {
		fmt.Fprintf(&restored, "nameserver %s\n", server)
	}
	restored.WriteString("options edns0\n")
	return system.WriteFileAtomic(path, []byte(restored.String()), 0o644)
}

func usableResolverContent(content []byte) bool {
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "nameserver" {
			continue
		}
		ip := net.ParseIP(strings.Trim(fields[1], "[]"))
		if ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() {
			return true
		}
	}
	return false
}
