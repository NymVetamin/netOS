// Package components устанавливает и удаляет части роутера по списку из
// конфигурации.
//
// Базовая установка netOS ставит только панель. Всё остальное появляется на
// машине тогда, когда администратор явно этого попросит, и исчезает, когда
// перестанет быть нужным. Это не только про дисковое место: каждая лишняя
// служба — это ещё один открытый порт и ещё один демон, который может упасть.
package components

import (
	"context"
	"fmt"
	"os"
	"path"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type Subsystem struct {
	Runner                system.Runner
	Packages              *system.Packages
	Systemd               *system.Systemd
	Logger                Logger
	ExternalMigrationPath string
}

type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}

var externalVersionTimeout = 10 * time.Second

func New(r system.Runner, logger Logger) *Subsystem {
	return &Subsystem{
		Runner:   r,
		Packages: system.NewPackages(r),
		Systemd:  system.NewSystemd(r),
		Logger:   logger,
	}
}

func (s *Subsystem) Name() string { return "components" }

func (s *Subsystem) Plan(old, new *config.Config) ([]apply.Action, error) {
	return s.PlanContext(context.Background(), old, new)
}

// PlanContext keeps the live package/unit probes attached to the caller. The
// API gives preview a latency budget; using context.Background here used to
// leave dozens of probes running after the browser had already timed out.
func (s *Subsystem) PlanContext(ctx context.Context, old, new *config.Config) ([]apply.Action, error) {
	var actions []apply.Action
	desired := desiredComponentState(new)
	protected := protectedComponentPackages(desired)
	snapshot, snapshotErr := s.liveSnapshot(ctx)
	if snapshotErr != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}

	for _, info := range config.Catalog {
		want := desired[info.ID]
		if info.Essential && !want {
			continue
		}
		if want {
			_, allInstalled := s.componentStateFrom(ctx, info, snapshot, snapshotErr == nil)
			if allInstalled {
				continue
			}
			actions = append(actions, apply.Action{
				Kind: "create", Target: info.Title,
				Detail: "установка, " + info.SizeHint,
			})
		} else {
			if !s.componentRemovableFrom(ctx, info, protected, snapshot, snapshotErr == nil) {
				continue
			}
			actions = append(actions, apply.Action{
				Kind: "delete", Target: info.Title, Detail: "удаление", Disruptive: true,
			})
		}
	}
	return actions, nil
}

type componentLiveSnapshot struct {
	packages map[string]bool
	disabled map[string]bool
}

// liveSnapshot collapses the catalog-wide state check to one dpkg-query and
// two systemctl calls. On a saturated single-core router the old per-item loop
// multiplied process scheduling latency into minutes.
func (s *Subsystem) liveSnapshot(ctx context.Context) (componentLiveSnapshot, error) {
	var packages, units []string
	seenPackages, seenUnits := map[string]bool{}, map[string]bool{}
	for _, info := range config.Catalog {
		for _, pkg := range info.Packages {
			if !seenPackages[pkg] {
				seenPackages[pkg] = true
				packages = append(packages, pkg)
			}
		}
		for _, unit := range info.Units {
			if !seenUnits[unit] {
				seenUnits[unit] = true
				units = append(units, unit)
			}
		}
	}
	installed, err := s.Packages.InstalledPackages(ctx, packages)
	if err != nil {
		return componentLiveSnapshot{}, err
	}
	disabled, err := s.Systemd.DisabledUnits(ctx, units)
	if err != nil {
		return componentLiveSnapshot{}, err
	}
	return componentLiveSnapshot{packages: installed, disabled: disabled}, nil
}

// Apply доводит состав установленного до описанного в конфигурации.
//
// Установка требует сети и может занять минуты, поэтому ошибка одного
// компонента не отменяет применение целиком: остальная конфигурация всё равно
// должна примениться, а о неудаче администратор узнает из журнала и панели.
func (s *Subsystem) Apply(ctx context.Context, cfg *config.Config) error {
	var failures []string
	desired := desiredComponentState(cfg)
	protected := protectedComponentPackages(desired)
	if err := s.migrateLegacyExternalOwnership(ctx, desired); err != nil {
		return fmt.Errorf("миграция владения внешними компонентами: %w", err)
	}

	for _, info := range config.Catalog {
		want := desired[info.ID]
		if info.Essential && !want {
			continue
		}

		if want {
			_, allInstalled := s.componentState(ctx, info)
			if allInstalled {
				continue
			}
			if err := s.install(ctx, info); err != nil {
				s.Logger.Warnf("компонент %s: %v", info.Title, err)
				failures = append(failures, info.Title)
			}
			continue
		}
		if !s.componentRemovable(ctx, info, protected) {
			continue
		}
		if err := s.removeProtected(ctx, info, protected); err != nil {
			s.Logger.Warnf("удаление компонента %s: %v", info.Title, err)
			failures = append(failures, "удалить "+info.Title)
		}
	}

	if len(failures) > 0 {
		return fmt.Errorf("не удалось изменить компоненты: %s", strings.Join(failures, ", "))
	}
	return nil
}

// migrateLegacyExternalOwnership bridges installations made before adjacent
// ownership markers existed.  Old netOS versions already treated a current
// binary at the catalog target as managed (including deleting it when the
// component was disabled), so adopting that exact legacy state preserves the
// previous contract.  The sentinel makes this a one-shot migration: a foreign
// binary placed at the target later is never silently adopted.
func (s *Subsystem) migrateLegacyExternalOwnership(ctx context.Context, desired map[string]bool) error {
	if s.ExternalMigrationPath == "" {
		return nil
	}
	data, err := os.ReadFile(s.ExternalMigrationPath)
	if err == nil {
		if string(data) != externalMigrationMark {
			return fmt.Errorf("неверный marker %s", s.ExternalMigrationPath)
		}
		info, statErr := os.Lstat(s.ExternalMigrationPath)
		if statErr != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("marker %s не является обычным файлом", s.ExternalMigrationPath)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			return fmt.Errorf("marker %s имеет права %04o вместо 0600", s.ExternalMigrationPath, info.Mode().Perm())
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}

	var created []string
	rollback := func() {
		for _, marker := range created {
			_ = os.Remove(marker)
		}
	}
	for _, info := range config.Catalog {
		if !info.External || !desired[info.ID] {
			continue
		}
		rel, ok := externalReleases[info.ID]
		if !ok || externalOwned(rel) || !externalTargetPresent(rel) || !s.externalCurrent(ctx, rel) {
			continue
		}
		marker := externalOwnerPath(rel)
		if err := system.WriteFileAtomic(marker, []byte(externalOwnerMark), 0o600); err != nil {
			rollback()
			return fmt.Errorf("marker %s: %w", info.ID, err)
		}
		created = append(created, marker)
		s.Logger.Infof("принято владение legacy-компонентом %s", info.Title)
	}
	if err := system.WriteFileAtomic(s.ExternalMigrationPath, []byte(externalMigrationMark), 0o600); err != nil {
		rollback()
		return err
	}
	return nil
}

func desiredComponentState(cfg *config.Config) map[string]bool {
	desired := map[string]bool{}
	if cfg == nil {
		return desired
	}
	for _, component := range cfg.Components {
		desired[component.ID] = component.Installed
	}
	return desired
}

func protectedComponentPackages(desired map[string]bool) map[string]bool {
	protected := map[string]bool{}
	for _, info := range config.Catalog {
		if !desired[info.ID] && !info.Essential {
			continue
		}
		for _, pkg := range info.Packages {
			protected[pkg] = true
		}
	}
	return protected
}

func (s *Subsystem) componentRemovable(ctx context.Context, info config.ComponentInfo, protected map[string]bool) bool {
	return s.componentRemovableFrom(ctx, info, protected, componentLiveSnapshot{}, false)
}

func (s *Subsystem) componentRemovableFrom(ctx context.Context, info config.ComponentInfo, protected map[string]bool, snapshot componentLiveSnapshot, useSnapshot bool) bool {
	if info.External {
		rel, ok := externalReleases[info.ID]
		return ok && externalOwned(rel)
	}
	for _, unit := range info.Units {
		disabled := snapshot.disabled[unit]
		if !useSnapshot {
			disabled = s.Systemd.IsDisabled(ctx, unit)
		}
		if !disabled {
			return true
		}
	}
	for _, pkg := range info.Packages {
		installed := snapshot.packages[pkg]
		if !useSnapshot {
			installed = s.Packages.Installed(ctx, pkg)
		}
		if !protected[pkg] && installed {
			return true
		}
	}
	return false
}

// componentState distinguishes a complete installation from a partial one.
// The latter must be completed when selected and fully purged when omitted.
func (s *Subsystem) componentState(ctx context.Context, info config.ComponentInfo) (anyInstalled, allInstalled bool) {
	return s.componentStateFrom(ctx, info, componentLiveSnapshot{}, false)
}

func (s *Subsystem) componentStateFrom(ctx context.Context, info config.ComponentInfo, snapshot componentLiveSnapshot, useSnapshot bool) (anyInstalled, allInstalled bool) {
	if info.External {
		rel, ok := externalReleases[info.ID]
		if !ok {
			return false, false
		}
		present := externalTargetPresent(rel)
		if !present {
			return false, false
		}
		return true, externalOwned(rel) && s.externalCurrent(ctx, rel)
	}
	if len(info.Packages) == 0 {
		return false, false
	}
	allInstalled = true
	for _, pkg := range info.Packages {
		installed := snapshot.packages[pkg]
		if !useSnapshot {
			installed = s.Packages.Installed(ctx, pkg)
		}
		anyInstalled = anyInstalled || installed
		allInstalled = allInstalled && installed
	}
	for _, unit := range info.Units {
		disabled := snapshot.disabled[unit]
		if !useSnapshot {
			disabled = s.Systemd.IsDisabled(ctx, unit)
		}
		allInstalled = allInstalled && disabled
	}
	return anyInstalled, allInstalled
}

func (s *Subsystem) install(ctx context.Context, info config.ComponentInfo) error {
	if info.External {
		return s.installExternal(ctx, info)
	}
	if len(info.Packages) == 0 {
		return nil
	}
	installed, err := s.Packages.Ensure(ctx, info.Packages...)
	if err != nil {
		return err
	}
	if len(installed) > 0 {
		s.Logger.Infof("установлен компонент %s (%s)", info.Title, strings.Join(installed, ", "))
	}

	// Штатные юниты отключаем: службами управляет netOS через собственные
	// юниты с генерируемыми конфигами. Иначе после установки пакета демон
	// поднимется со своим конфигом и займёт порт.
	for _, unit := range info.Units {
		if err := s.Systemd.Disable(ctx, unit); err != nil {
			return fmt.Errorf("disable stock unit %s: %w", unit, err)
		}
	}
	return nil
}

// installExternal ставит то, чего нет в репозиториях Debian.
//
// Такие компоненты качаются с сайта разработчика, поэтому установка вынесена
// в отдельный путь: она требует сети наружу и проверки подписи или суммы, а
// не просто apt-get install.
func (s *Subsystem) installExternal(ctx context.Context, info config.ComponentInfo) error {
	if rel, ok := externalReleases[info.ID]; ok {
		owned := externalOwned(rel)
		if s.externalCurrent(ctx, rel) && owned {
			return nil
		}
		if externalTargetPresent(rel) && !owned {
			return fmt.Errorf("target %s уже существует и не принадлежит netOS", rel.Target)
		}
		backup := rel.Target + ".netos-rollback"
		hadPrevious, err := backupExternalTarget(rel.Target, backup)
		if err != nil {
			return fmt.Errorf("backup existing %s: %w", info.ID, err)
		}
		cleanupBackup := func() { _ = os.Remove(backup) }
		if err := s.installRelease(ctx, info.ID, rel); err != nil {
			cleanupBackup()
			return err
		}
		if !s.externalCurrent(ctx, rel) {
			if hadPrevious {
				if err := restoreExternalTarget(rel.Target, backup); err != nil {
					return fmt.Errorf("installed %s does not report pinned version %s; restore previous binary: %w", info.ID, rel.Version, err)
				}
			} else if err := os.Remove(rel.Target); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("installed %s does not report pinned version %s; remove invalid binary: %w", info.ID, rel.Version, err)
			}
			return fmt.Errorf("installed %s does not report pinned version %s", info.ID, rel.Version)
		}
		if err := system.WriteFileAtomic(externalOwnerPath(rel), []byte(externalOwnerMark), 0o600); err != nil {
			if hadPrevious {
				if restoreErr := restoreExternalTarget(rel.Target, backup); restoreErr != nil {
					return fmt.Errorf("write ownership for %s: %v; restore previous binary: %w", info.ID, err, restoreErr)
				}
			} else {
				_ = os.Remove(rel.Target)
			}
			return fmt.Errorf("write ownership for %s: %w", info.ID, err)
		}
		cleanupBackup()
		return nil
	}
	switch info.ID {
	case "xray":
		return fmt.Errorf("установка компонента %s появится вместе с поддержкой самого компонента", info.Title)
	}
	return fmt.Errorf("неизвестный внешний компонент %s", info.ID)
}

func backupExternalTarget(target, backup string) (bool, error) {
	info, err := os.Lstat(target)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("target %s is not a regular file", target)
	}
	if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := os.Link(target, backup); err != nil {
		return false, err
	}
	return true, nil
}

func restoreExternalTarget(target, backup string) error {
	if err := os.Rename(backup, target); err == nil {
		return nil
	}
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(backup, target)
}

// externalCurrent проверяет закреплённую версию, а не просто наличие файла.
// Повторное применение любой настройки не должно зависеть от GitHub и заново
// заменять работающий бинарник; повреждённая или устаревшая копия при этом
// должна быть переустановлена обычным проверенным путём.
func (s *Subsystem) externalCurrent(ctx context.Context, rel externalRelease) bool {
	info, err := os.Stat(rel.Target)
	if err != nil || !info.Mode().IsRegular() || s.Runner == nil || len(rel.VersionArgs) == 0 {
		return false
	}
	probeCtx, cancel := context.WithTimeout(ctx, externalVersionTimeout)
	defer cancel()
	out, err := s.Runner.Run(probeCtx, rel.Target, rel.VersionArgs...)
	if err != nil {
		return false
	}
	return versionOutputMatches(out, rel.Version)
}

func versionOutputMatches(out, version string) bool {
	want := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(version), "v"), "V")
	if want == "" {
		return false
	}
	pattern := `(?i)(^|[^0-9a-z.])v?` + regexp.QuoteMeta(want) + `($|[^0-9a-z.+-])`
	return regexp.MustCompile(pattern).MatchString(out)
}

func (s *Subsystem) remove(ctx context.Context, info config.ComponentInfo) error {
	return s.removeProtected(ctx, info, nil)
}

func (s *Subsystem) removeProtected(ctx context.Context, info config.ComponentInfo, protected map[string]bool) error {
	if info.Essential {
		// Отключается функция, а не базовый инструмент, которым пользуется сам
		// netOS. В частности, iproute2 нельзя удалять вместе с QoS.
		return nil
	}
	for _, unit := range info.Units {
		if err := s.Systemd.Disable(ctx, unit); err != nil {
			return fmt.Errorf("disable stock unit %s: %w", unit, err)
		}
	}
	if info.External {
		// Удаляем только файл с явным ownership-маркером. Само имя в
		// /usr/local/bin не доказывает, что бинарник положил netOS.
		if rel, ok := externalReleases[info.ID]; ok {
			if !externalOwned(rel) {
				return nil
			}
			if err := os.Remove(rel.Target); err != nil && !os.IsNotExist(err) {
				return err
			}
			if err := os.Remove(externalOwnerPath(rel)); err != nil && !os.IsNotExist(err) {
				return err
			}
			s.Logger.Infof("удалён компонент %s", info.Title)
		}
		return nil
	}
	if len(info.Packages) == 0 {
		return nil
	}

	// Удаляем только то, что реально стоит: apt-get purge на отсутствующем
	// пакете возвращает ошибку и засоряет журнал.
	var present []string
	for _, p := range info.Packages {
		if !protected[p] && s.Packages.Installed(ctx, p) {
			present = append(present, p)
		}
	}
	if len(present) == 0 {
		return nil
	}

	// Dependencies installed by apt are marked automatic. Purging only the
	// top-level package leaves those binaries behind, so the component does not
	// really disappear and the attack surface remains. Let apt remove automatic
	// packages that are no longer needed by anything else.
	args := append([]string{"-o", "DPkg::Lock::Timeout=60", "purge", "--autoremove", "-y"}, present...)
	if _, err := s.Runner.Run(ctx, "apt-get", args...); err != nil {
		return err
	}
	s.Logger.Infof("удалён компонент %s", info.Title)
	return nil
}

// Health не проверяет ничего: неустановленный компонент не повод откатывать
// всю конфигурацию, а о неудаче установки уже сообщил Apply.
func (s *Subsystem) Health(ctx context.Context, cfg *config.Config) error { return nil }

// Status сообщает, что из каталога реально присутствует на машине. Панель
// показывает это рядом с желаемым состоянием, чтобы расхождение было видно.
func (s *Subsystem) Status(ctx context.Context) map[string]bool {
	out := map[string]bool{}
	snapshot, snapshotErr := s.liveSnapshot(ctx)
	if snapshotErr != nil && ctx.Err() != nil {
		return out
	}
	for _, info := range config.Catalog {
		if !info.External && len(info.Packages) == 0 {
			continue
		}
		_, out[info.ID] = s.componentStateFrom(ctx, info, snapshot, snapshotErr == nil)
	}
	return out
}

// Running сообщает, какие компоненты не просто установлены, а работают прямо
// сейчас: их демон поднят юнитом netOS.
//
// Установленный пакет и работающая служба — разные вещи, и по одному только
// «установлен» непонятно, кто из двух установленных серверов DHCP обслуживает
// сеть. Компоненты без собственного юнита (наборы адресов, утилиты
// диагностики) в ответе не появляются вовсе: работу измерять нечем.
func (s *Subsystem) Running(ctx context.Context) map[string]bool {
	// Один запрос на все юниты netOS, а не по одному на компонент: панель
	// спрашивает это состояние регулярно.
	active := s.Systemd.ActiveUnits(ctx, "netos-*.service")

	out := map[string]bool{}
	for _, info := range config.Catalog {
		if len(info.RunUnits) == 0 {
			continue
		}
		out[info.ID] = anyUnitActive(info.RunUnits, active)
	}
	return out
}

// anyUnitActive сверяет шаблоны юнитов компонента с работающими. Шаблон нужен
// для аплинков: netos-l2tp-<канал>.service именуется по идентификатору канала.
func anyUnitActive(patterns, active []string) bool {
	for _, pattern := range patterns {
		for _, unit := range active {
			if ok, err := path.Match(pattern, unit); err == nil && ok {
				return true
			}
		}
	}
	return false
}
