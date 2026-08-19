// Package netconf решает, кто именно настраивает сетевые интерфейсы роутера.
//
// Выбор в панели обязан что-то значить, поэтому подсистема делает две вещи:
// генерирует персистентную конфигурацию для выбранного механизма и отбирает
// интерфейсы у остальных. Без второй половины «netOS напрямую» означало бы
// лишь «netOS тоже что-то делает»: на машине, где сетью уже управляет
// systemd-networkd, он продолжает выдавать адрес по DHCP, netOS считает тот же
// адрес своим статическим, и кто победит — вопрос времени до истечения аренды.
//
// Режимы:
//
//   - netos — интерфейсы поднимает netOS через iproute2. systemd-networkd
//     получает описание, в котором линк управляемый, но пассивный: адресов он
//     не назначает и чужих не снимает.
//   - ifupdown, networkd — netOS дополнительно описывает сеть средствами
//     выбранного механизма, и бриджи, VLAN и адреса сегментов существуют уже
//     с загрузки, до старта netosd.
//
// Что попадает в описание, а что нет:
//
//   - L2 и адреса сегментов — попадают. Они статичны и полностью описываются
//     средствами обоих механизмов.
//   - Аплинки — только поднимаются. Метрики, проверки живости, переключение
//     между каналами и собственный клиент DHCP остаются за netOS; второй
//     клиент DHCP на том же интерфейсе сломал бы Multi-WAN.
//
// netOS применяет состояние сам во всех режимах: только так изменение
// вступает в силу сразу, а не после перезагрузки.
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
	// waitOnlineDropIn снимает требование к состоянию линка, которое netOS
	// сделал невыполнимым. 99 — чтобы применяться после чужих drop-in.
	waitOnlineDropIn = "/etc/systemd/system/systemd-networkd-wait-online.service.d/99-netos.conf"
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

	// Смена механизма кратковременно рвёт связность: тот, у кого забирают
	// интерфейс, снимает выданные им адреса, и netOS назначает свои заново.
	// Администратор должен видеть это до применения, а не узнать по обрыву.
	disruptive := old != nil && old.System.NetworkBackend != new.System.NetworkBackend

	switch new.System.NetworkBackend {
	case "ifupdown":
		return []apply.Action{{
			Kind: "update", Target: ifupdownPath,
			Detail: "конфигурация networking", Disruptive: disruptive,
		}}, nil
	case "networkd":
		return []apply.Action{{
			Kind: "update", Target: networkdDir,
			Detail: "конфигурация systemd-networkd", Disruptive: disruptive,
		}}, nil
	default:
		return []apply.Action{{
			Kind: "update", Target: "управление интерфейсами",
			Detail:     "интерфейсы переходят под прямое управление netOS",
			Disruptive: disruptive,
		}}, nil
	}
}

func (s *Subsystem) Apply(ctx context.Context, cfg *config.Config) error {
	backend := cfg.System.NetworkBackend

	// Описание неактивного механизма убираем: иначе после переключения на
	// машине останутся два описания одной сети, и какое из них отработает при
	// загрузке, будет зависеть от порядка запуска служб.
	if backend != "ifupdown" {
		if err := removeFile(ifupdownPath); err != nil {
			return err
		}
	}

	if backend != "netos" && backend != "" {
		// Требование к ожиданию сети снимает только прямое управление:
		// в остальных режимах адреса назначает сам механизм системы.
		if err := s.syncWaitOnline(ctx, false); err != nil {
			return err
		}
	}

	switch backend {
	case "ifupdown":
		return s.applyIfupdown(ctx, cfg)
	case "networkd":
		return s.applyNetworkd(ctx, cfg)
	}
	return s.applyNetOS(ctx, cfg)
}

// applyNetOS отбирает интерфейсы netOS у остальных механизмов настройки сети.
func (s *Subsystem) applyNetOS(ctx context.Context, cfg *config.Config) error {
	s.warnAboutIfupdown(cfg)

	// Отбирать нечего, если механизма нет или он не работает.
	if !s.unitPresent(ctx, "systemd-networkd.service") ||
		!s.unitActive(ctx, "systemd-networkd.service") {
		return s.syncWaitOnline(ctx, false)
	}

	if err := s.syncNetworkdFiles(ctx, passiveFiles(cfg)); err != nil {
		return err
	}
	return s.syncWaitOnline(ctx, true)
}

// syncWaitOnline снимает с ожидания сети требование, которое netOS сделал
// невыполнимым.
//
// Образы с netplan кладут в /run drop-in, требующий от аплинка состояния
// degraded или routable. Оба означают наличие адреса, а адрес при прямом
// управлении назначает netOS — и не может назначить вовремя: на облачных
// образах cloud-init сидит в sysinit.target и ждёт network-online, тогда как
// netosd не стартует раньше basic.target, который идёт после sysinit. Круг
// размыкается только двухминутным таймаутом, и ровно столько занимала загрузка.
//
// Свой drop-in сбрасывает ExecStart, и решение возвращается к тому, что
// написано у каждого линка в RequiredForOnline. Имя начинается с 99, потому что
// drop-in применяются в лексическом порядке имён, а netplan занимает 10.
func (s *Subsystem) syncWaitOnline(ctx context.Context, needed bool) error {
	content := []byte(`# Сгенерировано netOS. Правки будут перезаписаны при следующем применении.
#
# Требование к состоянию линка снято: адреса при прямом управлении назначает
# netOS, и решает RequiredForOnline в файлах /etc/systemd/network/05-netos-*.
[Service]
ExecStart=
ExecStart=/usr/lib/systemd/systemd-networkd-wait-online
`)

	if !needed {
		if _, err := os.Stat(waitOnlineDropIn); err != nil {
			return nil
		}
		if err := removeFile(waitOnlineDropIn); err != nil {
			return err
		}
		_, err := s.Runner.Run(ctx, "systemctl", "daemon-reload")
		return err
	}

	if !system.FileChanged(waitOnlineDropIn, content) {
		return nil
	}
	if err := system.WriteFileAtomic(waitOnlineDropIn, content, 0o644); err != nil {
		return fmt.Errorf("настройка ожидания сети: %w", err)
	}
	_, err := s.Runner.Run(ctx, "systemctl", "daemon-reload")
	return err
}

func (s *Subsystem) applyIfupdown(ctx context.Context, cfg *config.Config) error {
	if err := s.requireUnit(ctx, "networking.service", "ifupdown"); err != nil {
		return err
	}
	// Настройку взял на себя ifupdown — описания для networkd быть не должно.
	if err := s.syncNetworkdFiles(ctx, nil); err != nil {
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
	return s.syncNetworkdFiles(ctx, renderNetworkd(cfg))
}

// syncNetworkdFiles приводит наш набор файлов в /etc/systemd/network к
// требуемому и просит networkd перечитать конфигурацию, если что-то изменилось.
func (s *Subsystem) syncNetworkdFiles(ctx context.Context, files map[string]string) error {
	existing, err := filepath.Glob(filepath.Join(networkdDir, networkdPrefix+"*"))
	if err != nil {
		return err
	}
	changed := false

	// Сначала убираем своё лишнее: интерфейс могли удалить из конфигурации, и
	// его описание не должно пережить это.
	for _, path := range existing {
		if _, keep := files[filepath.Base(path)]; keep {
			continue
		}
		if err := removeFile(path); err != nil {
			return err
		}
		changed = true
	}

	if len(files) > 0 {
		if err := os.MkdirAll(networkdDir, 0o755); err != nil {
			return err
		}
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

// warnAboutIfupdown сообщает о том, что перекрыть нельзя.
//
// У ifupdown нет приоритетов: два описания одного интерфейса — это ошибка, а
// не переопределение. Молча оставить чужую строку тоже неправильно: при
// загрузке она поднимет второй клиент DHCP на интерфейсе netOS.
func (s *Subsystem) warnAboutIfupdown(cfg *config.Config) {
	if s.Logger == nil {
		return
	}
	paths, _ := filepath.Glob("/etc/network/interfaces.d/*")
	paths = append(paths, "/etc/network/interfaces")
	managed := managedInterfaces(cfg)

	for _, path := range paths {
		if path == ifupdownPath {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, name := range managed {
			if !mentionsInterface(string(data), name) {
				continue
			}
			s.Logger.Warnf(
				"%s настраивает интерфейс %s, которым управляет netOS: перекрыть эту запись нельзя — уберите её или отключите networking.service",
				path, name)
		}
	}
}

// mentionsInterface ищет объявление интерфейса, а не любое совпадение имени:
// eth0 не должен находиться внутри eth0.100.
func mentionsInterface(content, name string) bool {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "iface", "auto", "allow-hotplug":
			for _, f := range fields[1:] {
				if f == name {
					return true
				}
			}
		}
	}
	return false
}

// renderPassive отдаёт адресацию интерфейса netOS, оставляя его при этом
// видимым для systemd-networkd.
//
// Напрашивающийся `Unmanaged=yes` здесь не годится, и выяснилось это только
// перезагрузкой. Неуправляемые линки networkd не считает вовсе, и когда netOS
// забирает себе все интерфейсы, у него не остаётся ни одного:
// systemd-networkd-wait-online ждёт впустую весь свой таймаут и добавляет к
// загрузке две минуты, а консоль при этом выглядит зависшей.
//
// Поэтому линк остаётся управляемым, но пассивным: адресов networkd не
// назначает (нет ни DHCP, ни Address) и чужих не снимает (`KeepConfiguration`).
// Так он виден как configured, загрузка не задерживается, а network-online
// начинает означать ровно то, что нужно, — netOS настроил сеть.
func renderPassive(iface config.Interface, suppressIPv6 bool) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("# Сгенерировано netOS. Правки будут перезаписаны при следующем применении.")
	w("#")
	w("# Адресами этого интерфейса управляет netOS напрямую. Файл нужен, чтобы")
	w("# systemd-networkd не назначал свои и не снимал чужие.")
	w("[Match]")
	w("Name=%s", iface.Name)
	w("")
	w("[Network]")
	w("DHCP=no")
	// Без этого networkd снимает адреса и маршруты, которых нет в его файле, —
	// то есть стирает работу netOS.
	w("KeepConfiguration=yes")
	if suppressIPv6 {
		w("LinkLocalAddressing=no")
	}
	w("IPv6AcceptRA=no")
	w("")
	w("[Link]")
	// Линк держим поднятым: по нему пойдёт разговор клиента DHCP или PPPoE.
	w("ActivationPolicy=up")
	if !iface.Enabled {
		// Выключенный интерфейс не получит даже несущей, и ожидание сети при
		// загрузке упёрлось бы в таймаут из-за него.
		w("RequiredForOnline=no")
	} else {
		// carrier — то есть достаточно поднятого линка, адрес не требуется.
		//
		// Требовать routable нельзя: адрес назначает netOS, а он к этому
		// моменту ещё не работает и на облачных образах работать не может.
		// Там cloud-init сидит в sysinit.target и ждёт network-online, а
		// netosd не стартует раньше basic.target, который идёт после sysinit.
		// Круг размыкается только таймаутом systemd-networkd-wait-online в две
		// минуты — ровно столько и занимала загрузка.
		//
		// Именно carrier, а не degraded: degraded означает «есть link-local
		// адрес», а его мы отключаем через LinkLocalAddressing=no, и до этого
		// состояния линк не доберётся никогда. Проверено изолированно, через
		// wait-online -i: с degraded отказ по таймауту, с carrier — 15 мс.
		//
		// Это честная формулировка: при прямом управлении обязанности networkd
		// на этом линке ровно поднятием и заканчиваются.
		w("RequiredForOnline=carrier")
	}
	return b.String()
}

// passiveFiles собирает описания для режима прямого управления.
func passiveFiles(cfg *config.Config) map[string]string {
	files := map[string]string{}
	seen := map[string]bool{}
	for _, iface := range cfg.Interfaces {
		if iface.Name == "" || seen[iface.Name] {
			continue
		}
		seen[iface.Name] = true
		files[networkdPrefix+iface.Name+".network"] = renderPassive(iface, cfg.IPv6.Mode == "off")
	}
	return files
}

// managedInterfaces перечисляет интерфейсы, за которые отвечает netOS.
func managedInterfaces(cfg *config.Config) []string {
	seen := map[string]bool{}
	var names []string
	for _, iface := range cfg.Interfaces {
		if iface.Name == "" || seen[iface.Name] {
			continue
		}
		seen[iface.Name] = true
		names = append(names, iface.Name)
	}
	sort.Strings(names)
	return names
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

func (s *Subsystem) unitPresent(ctx context.Context, unit string) bool {
	out, err := s.Runner.Run(ctx, "systemctl", "list-unit-files", "--no-legend", unit)
	return err == nil && strings.TrimSpace(out) != ""
}

func (s *Subsystem) unitActive(ctx context.Context, unit string) bool {
	out, err := s.Runner.Run(ctx, "systemctl", "is-active", unit)
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == "active"
}

// Health ничего не проверяет: живое состояние сети приводят в порядок
// подсистемы interfaces, networks и wan, и именно их проверки поймают, если
// адрес после передачи управления не вернулся.
func (s *Subsystem) Health(ctx context.Context, cfg *config.Config) error { return nil }

// render — общий отпечаток конфигурации для сравнения в Plan.
func render(cfg *config.Config) string {
	switch cfg.System.NetworkBackend {
	case "ifupdown":
		return renderIfupdown(cfg)
	case "networkd":
		return joinFiles(renderNetworkd(cfg))
	}
	return joinFiles(passiveFiles(cfg))
}

func joinFiles(files map[string]string) string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		fmt.Fprintf(&b, "--- %s\n%s", name, files[name])
	}
	return b.String()
}

// RenderFor печатает то, что ляжет на машину при выбранном механизме.
// Используется командой netos render.
func RenderFor(cfg *config.Config) (string, error) {
	switch cfg.System.NetworkBackend {
	case "ifupdown":
		return "# " + ifupdownPath + "\n" + renderIfupdown(cfg), nil
	case "networkd", "netos", "":
		return render(cfg), nil
	}
	return "", fmt.Errorf("неизвестный способ настройки сети %q", cfg.System.NetworkBackend)
}

func removeFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("удаление %s: %w", path, err)
	}
	return nil
}
