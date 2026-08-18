// Package netconf генерирует персистентную конфигурацию сети для штатных
// механизмов Debian — ifupdown и systemd-networkd.
//
// Зачем это нужно, если netOS и так поднимает интерфейсы сам. netosd стартует
// после network.target, и до его запуска машина живёт с той сетью, которую
// подняла система. На выделенном роутере это терпимо, но администратор,
// у которого в организации принят свой способ настройки сети, вправе
// потребовать, чтобы бриджи, VLAN и адреса сегментов существовали с загрузки,
// а не появлялись через несколько секунд после неё.
//
// Что попадает в конфигурацию, а что нет:
//
//   - L2 и адреса сегментов — попадают. Они статичны и полностью описываются
//     средствами обоих механизмов.
//   - Аплинки — не попадают, кроме поднятия самого линка. Метрики, проверки
//     живости, переключение между каналами и собственный клиент DHCP остаются
//     за netOS; второй клиент DHCP на том же интерфейсе или чужой маршрут по
//     умолчанию сломали бы Multi-WAN. Поэтому аплинки описываются как manual.
//
// netOS продолжает применять состояние сам и при выбранном механизме: только
// так изменение вступает в силу сразу, а не после перезагрузки.
package netconf

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

const (
	ifupdownPath = "/etc/network/interfaces.d/netos.conf"
	networkdDir  = "/etc/systemd/network"
	// networkdPrefix отделяет наши файлы от чужих: чистим только своё.
	//
	// Номер стоит первым не для красоты. networkd применяет первый .network,
	// чей Match подошёл, а файлы перебирает в лексическом порядке: при имени
	// вида netos-20-... любой штатный 10-all.network оказался бы раньше, и
	// конфигурация netOS молча не работала бы. 05 ставит её раньше принятых
	// в дистрибутивах 10, 20 и 80.
	networkdPrefix = "05-netos-"
)

type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}

type Subsystem struct {
	Runner system.Runner
	Logger Logger
}

func New(r system.Runner, logger Logger) *Subsystem {
	return &Subsystem{Runner: r, Logger: logger}
}

func (s *Subsystem) Name() string { return "netconf" }

func (s *Subsystem) Plan(old, new *config.Config) ([]apply.Action, error) {
	if old != nil && old.System.NetworkBackend == new.System.NetworkBackend &&
		render(old) == render(new) {
		return nil, nil
	}
	switch new.System.NetworkBackend {
	case "ifupdown":
		return []apply.Action{{
			Kind: "update", Target: ifupdownPath, Detail: "конфигурация networking",
		}}, nil
	case "networkd":
		return []apply.Action{{
			Kind: "update", Target: networkdDir, Detail: "конфигурация systemd-networkd",
		}}, nil
	}
	if old != nil && old.System.NetworkBackend != "netos" {
		return []apply.Action{{
			Kind: "delete", Target: "персистентная конфигурация сети",
			Detail: "интерфейсами снова управляет только netOS",
		}}, nil
	}
	return nil, nil
}

func (s *Subsystem) Apply(ctx context.Context, cfg *config.Config) error {
	backend := cfg.System.NetworkBackend

	// Файлы неактивных механизмов убираем всегда: иначе после переключения на
	// машине останутся два описания одной сети, и какое из них отработает при
	// загрузке, будет зависеть от порядка запуска служб.
	if backend != "ifupdown" {
		if err := removeFile(ifupdownPath); err != nil {
			return err
		}
	}
	if backend != "networkd" {
		if err := removeNetworkdFiles(); err != nil {
			return err
		}
	}

	switch backend {
	case "ifupdown":
		return s.applyIfupdown(ctx, cfg)
	case "networkd":
		return s.applyNetworkd(ctx, cfg)
	}
	return nil
}

func (s *Subsystem) applyIfupdown(ctx context.Context, cfg *config.Config) error {
	if err := s.requireUnit(ctx, "networking.service", "ifupdown"); err != nil {
		return err
	}
	content := []byte(renderIfupdown(cfg))
	if !system.FileChanged(ifupdownPath, content) {
		return nil
	}
	return system.WriteFileAtomic(ifupdownPath, content, 0o644)
}

func (s *Subsystem) applyNetworkd(ctx context.Context, cfg *config.Config) error {
	if err := s.requireUnit(ctx, "systemd-networkd.service", "systemd-networkd"); err != nil {
		return err
	}

	files := renderNetworkd(cfg)
	if err := os.MkdirAll(networkdDir, 0o755); err != nil {
		return err
	}

	// Сначала убираем свои файлы, которых больше нет в наборе: интерфейс могли
	// удалить из конфигурации, и его описание не должно пережить это.
	existing, err := filepath.Glob(filepath.Join(networkdDir, networkdPrefix+"*"))
	if err != nil {
		return err
	}
	changed := false
	for _, path := range existing {
		if _, keep := files[filepath.Base(path)]; keep {
			continue
		}
		if err := removeFile(path); err != nil {
			return err
		}
		changed = true
	}

	for name, content := range files {
		path := filepath.Join(networkdDir, name)
		if !system.FileChanged(path, []byte(content)) {
			continue
		}
		if err := system.WriteFileAtomic(path, []byte(content), 0o644); err != nil {
			return err
		}
		changed = true
	}

	if !changed {
		return nil
	}
	// Перечитать конфигурацию просим только работающий networkd. Запускать его
	// сами не имеем права: на машине, где сеть держит ifupdown, это устроило бы
	// драку двух служб за одни и те же интерфейсы.
	if s.unitActive(ctx, "systemd-networkd.service") {
		if _, err := s.Runner.Run(ctx, "networkctl", "reload"); err != nil {
			return fmt.Errorf("перечитывание конфигурации systemd-networkd: %w", err)
		}
	}
	return nil
}

// requireUnit проверяет, что выбранный механизм вообще есть на машине, и
// предупреждает, если он есть, но выключен.
//
// Отсутствие — ошибка: администратор выбрал способ настройки, которого нет, и
// после перезагрузки остался бы без сети. Выключенное состояние — только
// предупреждение: включать чужую службу за администратора нельзя, она может
// быть выключена намеренно.
func (s *Subsystem) requireUnit(ctx context.Context, unit, name string) error {
	out, err := s.Runner.Run(ctx, "systemctl", "list-unit-files", "--no-legend", unit)
	if err != nil || strings.TrimSpace(out) == "" {
		return fmt.Errorf(
			"выбран способ настройки сети %q, но служба %s на машине не найдена", name, unit)
	}
	if s.Logger != nil && !strings.Contains(out, "enabled") {
		s.Logger.Warnf(
			"служба %s выключена: конфигурация сгенерирована, но при загрузке применена не будет", unit)
	}
	return nil
}

func (s *Subsystem) unitActive(ctx context.Context, unit string) bool {
	out, err := s.Runner.Run(ctx, "systemctl", "is-active", unit)
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == "active"
}

// Health ничего не проверяет: живое состояние сети приводят в порядок
// подсистемы interfaces, networks и wan, а эти файлы отрабатывают только при
// следующей загрузке. Откатывать применение из-за них нечего.
func (s *Subsystem) Health(ctx context.Context, cfg *config.Config) error { return nil }

// render — общий отпечаток конфигурации для сравнения в Plan.
func render(cfg *config.Config) string {
	switch cfg.System.NetworkBackend {
	case "ifupdown":
		return renderIfupdown(cfg)
	case "networkd":
		var b strings.Builder
		files := renderNetworkd(cfg)
		names := make([]string, 0, len(files))
		for name := range files {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(&b, "--- %s\n%s", name, files[name])
		}
		return b.String()
	}
	return ""
}

func removeFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("удаление %s: %w", path, err)
	}
	return nil
}

func removeNetworkdFiles() error {
	paths, err := filepath.Glob(filepath.Join(networkdDir, networkdPrefix+"*"))
	if err != nil {
		return err
	}
	for _, path := range paths {
		if err := removeFile(path); err != nil {
			return err
		}
	}
	return nil
}

// RenderFor печатает персистентную конфигурацию для выбранного механизма.
// Используется командой netos render: администратор должен видеть, что именно
// ляжет на машину, не дожидаясь применения.
func RenderFor(cfg *config.Config) (string, error) {
	switch cfg.System.NetworkBackend {
	case "ifupdown":
		return "# " + ifupdownPath + "\n" + renderIfupdown(cfg), nil
	case "networkd":
		return render(cfg), nil
	case "netos", "":
		return "# Интерфейсами управляет netOS напрямую, файлы не генерируются.\n", nil
	}
	return "", fmt.Errorf("неизвестный способ настройки сети %q", cfg.System.NetworkBackend)
}
