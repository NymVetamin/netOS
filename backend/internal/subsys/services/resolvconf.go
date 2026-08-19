package services

import (
	"context"
	"encoding/json"
	"fmt"
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
	return &SystemResolver{Runner: r, Systemd: system.NewSystemd(r)}
}

const (
	resolvConfPath = "/etc/resolv.conf"
	// resolvStatePath помнит, чем был /etc/resolv.conf до того, как netOS его
	// забрал: сам файл вернуть иначе будет неоткуда.
	resolvStatePath = "/var/lib/netos/resolv-conf.state"
	resolvedUnit    = "systemd-resolved.service"
)

// resolvState — исходное состояние резолвера машины.
type resolvState struct {
	// Kind: symlink, file или absent.
	Kind string `json:"kind"`
	// Target — цель симлинка, Content — содержимое обычного файла.
	Target  string `json:"target,omitempty"`
	Content string `json:"content,omitempty"`
	// ResolvedEnabled помнит, работал ли systemd-resolved: включать обратно
	// то, что было выключено и до netOS, — значит менять чужую машину.
	ResolvedEnabled bool `json:"resolved_enabled"`
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

	state := resolvState{ResolvedEnabled: u.resolvedEnabled(ctx)}
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
		state.Kind, state.Target = "symlink", target
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

// resolvedEnabled сообщает, работал ли systemd-resolved до нас.
func (u *SystemResolver) resolvedEnabled(ctx context.Context) bool {
	if u.Systemd.IsActive(ctx, resolvedUnit) {
		return true
	}
	out, _ := u.Runner.Run(ctx, "systemctl", "is-enabled", resolvedUnit)
	switch strings.TrimSpace(out) {
	case "enabled", "enabled-runtime", "alias", "indirect":
		return true
	}
	return false
}

// Release возвращает системе её резолвер. Вызывается, когда DNS выключен в
// панели, и при удалении netOS: подсистема владеет файлом целиком, а значит
// обязана уметь его отдать.
func (u *SystemResolver) Release(ctx context.Context) error {
	resolvedWanted, err := RestoreSystemResolverFiles(u.Root)
	if err != nil {
		return err
	}
	// Включённым обратно оказывается только то, что работало до netOS.
	if resolvedWanted {
		_, _ = u.Runner.Run(ctx, "systemctl", "enable", "--now", resolvedUnit)
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
	at := func(p string) string {
		if root == "" {
			return p
		}
		return filepath.Join(root, p)
	}

	statePath := at(resolvStatePath)
	data, err := os.ReadFile(statePath)
	if os.IsNotExist(err) {
		// Файл никогда не был нашим — трогать его нечего.
		return false, nil
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
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return false, err
		}
		if err := os.Symlink(state.Target, path); err != nil {
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
	}
	if err := os.Remove(statePath); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	return state.ResolvedEnabled, nil
}
