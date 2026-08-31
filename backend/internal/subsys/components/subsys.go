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
	"strings"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type Subsystem struct {
	Runner   system.Runner
	Packages *system.Packages
	Systemd  *system.Systemd
	Logger   Logger
}

type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}

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
	var actions []apply.Action
	desired := map[string]bool{}
	for _, component := range new.Components {
		desired[component.ID] = component.Installed
	}

	for _, info := range config.Catalog {
		want := desired[info.ID]
		anyInstalled, allInstalled := s.componentState(context.Background(), info)
		if info.Essential && !want {
			continue
		}
		if want && allInstalled || !want && !anyInstalled {
			continue
		}
		if want {
			actions = append(actions, apply.Action{
				Kind: "create", Target: info.Title,
				Detail: "установка, " + info.SizeHint,
			})
		} else {
			actions = append(actions, apply.Action{
				Kind: "delete", Target: info.Title, Detail: "удаление", Disruptive: true,
			})
		}
	}
	return actions, nil
}

// Apply доводит состав установленного до описанного в конфигурации.
//
// Установка требует сети и может занять минуты, поэтому ошибка одного
// компонента не отменяет применение целиком: остальная конфигурация всё равно
// должна примениться, а о неудаче администратор узнает из журнала и панели.
func (s *Subsystem) Apply(ctx context.Context, cfg *config.Config) error {
	var failures []string
	desired := map[string]bool{}
	for _, component := range cfg.Components {
		desired[component.ID] = component.Installed
	}

	for _, info := range config.Catalog {
		want := desired[info.ID]
		anyInstalled, allInstalled := s.componentState(ctx, info)
		if info.Essential && !want {
			continue
		}
		if want && allInstalled || !want && !anyInstalled {
			continue
		}

		if want {
			if err := s.install(ctx, info); err != nil {
				s.Logger.Warnf("компонент %s: %v", info.Title, err)
				failures = append(failures, info.Title)
			}
			continue
		}
		if err := s.remove(ctx, info); err != nil {
			s.Logger.Warnf("удаление компонента %s: %v", info.Title, err)
			failures = append(failures, "удалить "+info.Title)
		}
	}

	if len(failures) > 0 {
		return fmt.Errorf("не удалось изменить компоненты: %s", strings.Join(failures, ", "))
	}
	return nil
}

// componentState distinguishes a complete installation from a partial one.
// The latter must be completed when selected and fully purged when omitted.
func (s *Subsystem) componentState(ctx context.Context, info config.ComponentInfo) (anyInstalled, allInstalled bool) {
	if info.External {
		installed := externalInstalled(info.ID)
		return installed, installed
	}
	if len(info.Packages) == 0 {
		return false, false
	}
	allInstalled = true
	for _, pkg := range info.Packages {
		installed := s.Packages.Installed(ctx, pkg)
		anyInstalled = anyInstalled || installed
		allInstalled = allInstalled && installed
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
		_ = s.Systemd.Disable(ctx, unit)
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
		if s.externalCurrent(ctx, rel) {
			return nil
		}
		return s.installRelease(ctx, info.ID, rel)
	}
	switch info.ID {
	case "xray":
		return fmt.Errorf("установка компонента %s появится вместе с поддержкой самого компонента", info.Title)
	}
	return fmt.Errorf("неизвестный внешний компонент %s", info.ID)
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
	out, err := s.Runner.Run(ctx, rel.Target, rel.VersionArgs...)
	if err != nil {
		return false
	}
	want := strings.TrimPrefix(rel.Version, "v")
	return want != "" && strings.Contains(out, want)
}

func (s *Subsystem) remove(ctx context.Context, info config.ComponentInfo) error {
	if info.Essential {
		// Отключается функция, а не базовый инструмент, которым пользуется сам
		// netOS. В частности, iproute2 нельзя удалять вместе с QoS.
		return nil
	}
	for _, unit := range info.Units {
		_ = s.Systemd.Disable(ctx, unit)
	}
	if info.External {
		// Внешний компонент — это один файл, который мы же и положили;
		// удаляем его, иначе выключённый компонент останется на диске.
		if rel, ok := externalReleases[info.ID]; ok {
			if err := os.Remove(rel.Target); err != nil && !os.IsNotExist(err) {
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
		if s.Packages.Installed(ctx, p) {
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
	for _, info := range config.Catalog {
		if !info.External && len(info.Packages) == 0 {
			continue
		}
		_, out[info.ID] = s.componentState(ctx, info)
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
