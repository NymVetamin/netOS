// Команда netosd — демон netOS: применяет конфигурацию и обслуживает
// веб-панель.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/netos-router/netos/internal/api"
	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/bootstrap"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/manage"
	"github.com/netos-router/netos/internal/render"
	"github.com/netos-router/netos/internal/runtime"
	"github.com/netos-router/netos/internal/store"
	"github.com/netos-router/netos/internal/subsys/channels"
	"github.com/netos-router/netos/internal/subsys/components"
	"github.com/netos-router/netos/internal/subsys/ddns"
	"github.com/netos-router/netos/internal/subsys/firewall"
	"github.com/netos-router/netos/internal/subsys/hostsettings"
	"github.com/netos-router/netos/internal/subsys/multiwan"
	"github.com/netos-router/netos/internal/subsys/netconf"
	"github.com/netos-router/netos/internal/subsys/netiface"
	"github.com/netos-router/netos/internal/subsys/policy"
	"github.com/netos-router/netos/internal/subsys/qos"
	"github.com/netos-router/netos/internal/subsys/routing"
	"github.com/netos-router/netos/internal/subsys/services"
	"github.com/netos-router/netos/internal/subsys/sysctl"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
	"github.com/netos-router/netos/internal/subsys/wifi"
	"github.com/netos-router/netos/internal/system"
)

// version задаётся релизной сборкой через -ldflags "-X main.version=vX.Y.Z".
var (
	version = "dev"
	// Variable rather than a constant so tests can verify first-boot credential
	// creation and CLI lifecycle without ever touching production paths.
	credentialsPath = "/var/lib/netos/initial-credentials"
	stateDir        = "/var/lib/netos/generated"
	// credentialsPath — файл с учётными данными первого запуска. Установщик
	// читает его вместо разбора журнала: журнал хранит записи прошлых
	// установок, и вытащить из него именно текущий пароль надёжно нельзя.
	// Файл удаляется, как только администратор сменит пароль.
	tlsDir        = "/etc/netos/tls"
	leasePath     = "/var/lib/netos/dnsmasq.leases"
	readyPath     = "/run/netosd.ready"
	detectInitial = bootstrap.Detect
	newRunner     = func() system.Runner { return system.NewExec() }
)

func main() {
	// /usr/local/bin/netos — ссылка на тот же бинарник. По публичному имени он
	// работает как управляющая команда; netosd остаётся только демоном.
	if strings.TrimSuffix(filepath.Base(os.Args[0]), filepath.Ext(os.Args[0])) == "netos" {
		if err := manage.New(version).Execute(context.Background(), os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, "Ошибка:", err)
			os.Exit(1)
		}
		return
	}

	var (
		dbPath      = flag.String("db", "/var/lib/netos/netos.db", "путь к базе данных")
		dryRun      = flag.Bool("dry-run", false, "показать действия, ничего не применяя")
		verbose     = flag.Bool("v", false, "подробный журнал выполняемых команд")
		showPlan    = flag.Bool("plan", false, "показать план применения и выйти")
		render      = flag.String("render", "", renderFlagHelp())
		initOnly    = flag.Bool("init", false, "создать стартовую конфигурацию и выйти")
		applyNow    = flag.Bool("apply", false, "применить активную конфигурацию и выйти")
		captureBase = flag.Bool("capture-system-baseline", false, "сохранить состояние системы до первой установки и выйти")
		showPort    = flag.Bool("panel-port", false, "показать фактический порт панели и выйти")
		showVersion = flag.Bool("version", false, "показать версию и выйти")
	)
	flag.Parse()
	daemonMode := !*dryRun && !*showPlan && *render == "" && !*initOnly && !*applyNow && !*captureBase && !*showPort && !*showVersion
	if daemonMode {
		// Type=simple становится active до окончания стартового Apply. Старый
		// маркер снимает сам новый процесс: команды обслуживания ждут готовой
		// конфигурации, а не только существующего PID.
		_ = os.Remove(readyPath)
	}
	if *showVersion {
		fmt.Printf("netOS %s\n", version)
		return
	}

	logger := &stdLogger{}
	runner := newRunner()
	if *verbose {
		if execRunner, ok := runner.(*system.Exec); ok {
			execRunner.OnCommand = func(name string, args []string) {
				log.Printf("  $ %s %v", name, args)
			}
		}
	}
	if *captureBase {
		if err := manage.CaptureSystemBaseline(context.Background(), runner); err != nil {
			log.Fatalf("не удалось сохранить состояние системы до установки: %v", err)
		}
		fmt.Println("Состояние системы до установки сохранено.")
		return
	}
	for _, dir := range []string{filepath.Dir(*dbPath), stateDir} {
		if err := system.CleanupAtomicTemps(dir); err != nil {
			logger.Warnf("уборка незавершённых временных файлов в %s: %v", dir, err)
		}
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("не удалось открыть базу данных: %v", err)
	}
	defer st.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Конфигурация: активная ревизия либо, если её нет, свежесобранная по
	// фактическому состоянию машины.
	cfg, revID, err := loadOrBootstrap(ctx, st, runner, logger)
	if err != nil {
		log.Fatalf("не удалось получить конфигурацию: %v", err)
	}
	if *showPort {
		fmt.Println(cfg.System.Panel.Port)
		return
	}

	if *initOnly {
		fmt.Printf("Стартовая конфигурация создана, ревизия %d\n", revID)
		printSummary(cfg)
		return
	}

	engine := apply.NewEngine(logger, *dryRun)
	multiWAN := multiwan.New(runner, stateDir, logger)
	channelMonitor := channels.New(runner, stateDir, logger)
	ddnsController := ddns.New(logger)
	if err := registerSubsystems(engine, runner, logger, multiWAN, channelMonitor, ddnsController); err != nil {
		log.Fatalf("регистрация подсистем: %v", err)
	}

	// Откат должен оставлять след: ревизия помечается откаченной, событие
	// попадает в журнал аудита. Иначе история конфигураций будет врать.
	engine.OnRollback = func(info apply.RollbackInfo) {
		if err := st.SetRevisionState(info.Revision, store.StateRolledBack); err != nil {
			logger.Warnf("не удалось пометить ревизию %d откаченной: %v", info.Revision, err)
		}
		_ = st.Audit(store.AuditEntry{
			User:    "system",
			Action:  "rollback",
			Target:  strconv.FormatInt(info.Revision, 10),
			Detail:  info.Reason + ": " + info.Details,
			Success: true,
		})
	}

	if *render != "" {
		if err := renderArtifact(*render, cfg); err != nil {
			log.Fatalf("%v", err)
		}
		return
	}

	if *showPlan {
		// Применённое состояние знает работающий демон, а команда plan — это
		// отдельный процесс со своим пустым движком. Без явного old план
		// строился бы от пустоты и на любой настроенной машине печатал бы
		// установку с нуля, включая пометку «разрывает связность».
		//
		// Взятая из базы активная ревизия — это то, что демон применил.
		// Подсистемы, которые сверяются с живой системой, на таком сравнении
		// покажут реальное расхождение, а остальные промолчат.
		var applied *config.Config
		if rev, err := st.ActiveRevision(); err == nil {
			applied = rev.Config
		}
		actions, err := engine.PlanFrom(applied, cfg)
		if err != nil {
			log.Fatalf("построение плана: %v", err)
		}
		printPlan(actions)
		return
	}

	// Проверка конфигурации до любых действий.
	if res := cfg.Validate(); len(res.Problems) > 0 {
		for _, p := range res.Problems {
			log.Printf("[%s] %s: %s", p.Severity, p.Path, p.Message)
		}
		if res.HasErrors() {
			log.Fatalf("конфигурация содержит ошибки, применение отменено")
		}
	}

	// Применение при старте подтверждения не требует: подтверждать некому.
	logger.Infof("применяю конфигурацию (ревизия %d)", revID)
	transitioned := false
	if rev, err := st.Revision(revID); err == nil && rev.State != store.StateActive {
		if err := st.SetRevisionState(revID, store.StateApplying); err != nil {
			log.Fatalf("не удалось пометить ревизию применяемой: %v", err)
		}
		transitioned = true
	}
	if _, err := engine.Apply(ctx, cfg, revID, false); err != nil {
		if transitioned {
			_ = st.SetRevisionState(revID, store.StateRolledBack)
		}
		log.Fatalf("применение не удалось: %v", err)
	}
	if err := st.MarkActive(revID); err != nil {
		logger.Warnf("не удалось пометить ревизию активной: %v", err)
	}
	logger.Infof("конфигурация применена")
	if *applyNow {
		printSummary(cfg)
		return
	}
	go multiWAN.Run(ctx, engine.Current)
	go channelMonitor.Run(ctx, engine.Current)
	go ddnsController.Run(ctx, engine.Current)

	// Первый запуск: заводим администратора и печатаем учётные данные.
	// Дальше пароль знает только владелец машины.
	if err := ensureAdmin(st, cfg, logger); err != nil {
		log.Fatalf("не удалось создать учётную запись администратора: %v", err)
	}

	collector := runtime.NewCollector(runner, leasePath)
	collector.LeaseProvider = func() string {
		if current := engine.Current(); current != nil {
			return current.DHCP.Provider
		}
		return "dnsmasq"
	}
	traffic := runtime.NewTrafficHistory("/var/lib/netos/traffic-history.json", collector)
	go traffic.Run(ctx)
	panel := api.New(st, engine, collector, logger)
	panel.Traffic = traffic
	panel.Maintenance = api.NewMaintenance(runner)
	// Каталог компонентов панель показывает вместе с живым состоянием машины:
	// что установлено и чей демон работает прямо сейчас.
	panel.Components = components.New(runner, logger)
	panel.DDNS = ddnsController
	if daemonMode {
		panel.Ready = func() error {
			return system.WriteFileAtomic(readyPath, []byte(strconv.FormatInt(revID, 10)+"\n"), 0o644)
		}
		defer os.Remove(readyPath)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		logger.Infof("получен сигнал завершения")
		cancel()
	}()

	if err := panel.Start(ctx, cfg, tlsDir); err != nil {
		log.Fatalf("панель остановлена с ошибкой: %v", err)
	}
	logger.Infof("завершение работы")
}

// ensureAdmin создаёт учётную запись при первом запуске. Открытый пароль
// сохраняется только в root-only initial-credentials: stdout демона попадает
// в systemd journal и для секретов непригоден.
func ensureAdmin(st *store.Store, cfg *config.Config, logger apply.Logger) error {
	count, err := st.CountUsers()
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	password, err := api.GeneratePassword(16)
	if err != nil {
		return err
	}
	hash, err := api.HashPassword(password)
	if err != nil {
		return err
	}
	if _, err := st.CreateUser("admin", hash, "admin"); err != nil {
		return err
	}

	addrs := panelAddresses(cfg)
	if err := writeCredentials(addrs, cfg.System.Panel.Port, password); err != nil {
		logger.Warnf("не удалось сохранить файл с учётными данными: %v", err)
	}
	printReady(os.Stdout, addrs, cfg.System.Panel.Port)

	logger.Infof("создана учётная запись admin; начальные данные сохранены в %s с правами root", credentialsPath)
	return nil
}

// printReady пишет только несекретную часть сообщения запуска. stdout демона
// сохраняется в systemd journal, поэтому пароль допустим лишь в root-only
// initial-credentials, откуда его отдельно читает интерактивный установщик.
func printReady(w io.Writer, addrs []string, panelPort int) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "==============================================================")
	fmt.Fprintln(w, "  netOS готов к работе")
	fmt.Fprintln(w)
	port := strconv.Itoa(panelPort)
	for i, a := range addrs {
		label := "  Адрес панели:  "
		if i > 0 {
			label = "                 "
		}
		fmt.Fprintln(w, label+"https://"+a+":"+port)
	}
	fmt.Fprintln(w, "  Начальные учётные данные: /var/lib/netos/initial-credentials (только root)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Сертификат самоподписанный — браузер предупредит об этом.")
	fmt.Fprintln(w, "==============================================================")
	fmt.Fprintln(w)
}

// writeCredentials сохраняет данные первого входа с правами только для root.
func writeCredentials(addrs []string, port int, password string) error {
	var b strings.Builder
	for i, a := range addrs {
		label := "Адрес панели:  "
		if i > 0 {
			label = "               "
		}
		fmt.Fprintln(&b, label+"https://"+a+":"+strconv.Itoa(port))
	}
	fmt.Fprintln(&b, "Пользователь:  admin")
	fmt.Fprintln(&b, "Пароль:        "+password)
	return system.WriteFileAtomic(credentialsPath, []byte(b.String()), 0o600)
}

// panelAddresses перечисляет адреса, по которым панель реально открывается.
//
// Показывать только адрес локальной сети недостаточно: на машине с одной
// сетевой картой этот адрес висит на виртуальном интерфейсе, и добраться до
// него снаружи невозможно. Поэтому выводим и адрес аплинка тоже — пусть
// администратор выберет тот, до которого у него есть маршрут.
func panelAddresses(cfg *config.Config) []string {
	var addrs []string
	add := func(cidr string) {
		if cidr == "" {
			return
		}
		host := cidr
		if i := strings.IndexByte(cidr, '/'); i > 0 {
			host = cidr[:i]
		}
		for _, existing := range addrs {
			if existing == host {
				return
			}
		}
		addrs = append(addrs, host)
	}

	for _, n := range cfg.Networks {
		if n.Enabled {
			add(n.RouterAddress)
		}
	}
	for _, w := range cfg.WANs {
		if w.Enabled {
			add(w.Address)
		}
	}
	if len(addrs) == 0 {
		addrs = append(addrs, cfg.System.Hostname)
	}
	return addrs
}

func loadOrBootstrap(ctx context.Context, st *store.Store, runner system.Runner, logger apply.Logger) (*config.Config, int64, error) {
	rev, err := st.ActiveRevision()
	if err == nil {
		return rev.Config, rev.ID, nil
	}
	if err != store.ErrNotFound {
		return nil, 0, err
	}

	// Активной ревизии нет — либо первый запуск, либо предыдущая была
	// откачена. Берём последнюю, а если нет и её — строим стартовую.
	if latest, err := st.LatestRevision(); err == nil {
		logger.Infof("активной ревизии нет, беру последнюю (%d)", latest.ID)
		return latest.Config, latest.ID, nil
	} else if err != store.ErrNotFound {
		return nil, 0, fmt.Errorf("чтение последней ревизии: %w", err)
	}

	logger.Infof("конфигурации нет, определяю параметры машины")
	detected, err := detectInitial(ctx, runner)
	if err != nil {
		return nil, 0, fmt.Errorf("определение параметров: %w", err)
	}
	logger.Infof("аплинк: %s (%s), свободные интерфейсы: %v",
		detected.WANInterface, detected.WANAddress, detected.LANCandidates)

	cfg := bootstrap.BuildInitial(detected)
	if value := strings.TrimSpace(os.Getenv("NETOS_INITIAL_PORT")); value != "" {
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 || port == cfg.DNS.Port {
			return nil, 0, fmt.Errorf("NETOS_INITIAL_PORT имеет недопустимое значение %q", value)
		}
		cfg.System.Panel.Port = port
	}
	id, err := st.CreateRevision(cfg, "system", "стартовая конфигурация")
	if err != nil {
		return nil, 0, err
	}
	return cfg, id, nil
}

func registerSubsystems(engine *apply.Engine, runner system.Runner, logger apply.Logger, multiWAN *multiwan.Controller, channelMonitor *channels.Subsystem, ddnsController *ddns.Controller) error {
	svc := services.NewManager(runner)
	componentSubsystem := components.New(runner, logger)
	componentSubsystem.ExternalMigrationPath = filepath.Join(filepath.Dir(stateDir), "external-ownership-v1")

	subsystems := []apply.Subsystem{
		componentSubsystem,
		hostsettings.New(runner),
		sysctl.NewCore(runner),
		sysctl.NewIPv6(runner),
		netiface.NewInterfaces(runner),
		netiface.NewNetworks(runner),
		netiface.NewWAN(runner),
		multiWAN,
		qos.New(runner, stateDir),
		netconf.New(runner, logger),
		routing.New(runner),
		channelMonitor,
		vpnservers.New(runner, stateDir),
		policy.New(runner, stateDir),
		wifi.New(runner, stateDir),
		firewall.New(runner, stateDir),
		policy.NewCleanup(runner, stateDir),
		services.NewDHCP(svc),
		services.NewDNS(svc),
		ddnsController,
	}
	for _, s := range subsystems {
		if err := engine.Register(s); err != nil {
			return err
		}
	}
	return nil
}

// renderableArtifacts — что умеет печатать netosd -render. Список общий с
// командой netos render, чтобы справка не разошлась с действительностью.
var renderableArtifacts = render.IDs()

func renderFlagHelp() string {
	return "напечатать сгенерированный артефакт (" + strings.Join(renderableArtifacts, "|") + ") и выйти"
}

func renderArtifact(kind string, cfg *config.Config) error {
	if _, ok := render.ByID(kind); !ok {
		return fmt.Errorf(
			"неизвестный артефакт %q (доступны: %s)", kind, strings.Join(renderableArtifacts, ", "))
	}
	out, err := render.Render(kind, cfg)
	if err != nil {
		return err
	}
	fmt.Print(out)
	return nil
}

// printPlan печатает расхождение живой системы с конфигурацией.
//
// Заголовок здесь не украшение. Команда называется plan, и первый вопрос к её
// выводу — что именно показано: то, что уже сделано, или то, что будет
// сделано. Отвечаем прямо в выводе, а не отправляем в документацию.
func printPlan(actions []apply.Action) {
	if len(actions) == 0 {
		fmt.Println("Живая система соответствует конфигурации: применять нечего.")
		fmt.Println()
		fmt.Println("netos plan сравнивает состояние машины с активной конфигурацией netOS")
		fmt.Println("и печатает, что изменилось бы при её применении. Сам он ничего не меняет.")
		return
	}

	fmt.Println("Живая система расходится с конфигурацией netOS.")
	fmt.Println("Ниже — что сделал бы netOS, если применить конфигурацию сейчас.")
	fmt.Println("Сама команда ничего не меняет: применяет netosd — из панели или при запуске.")
	fmt.Println()
	fmt.Printf("Действий: %d\n\n", len(actions))

	// Порядок не трогаем: действия перечислены в порядке apply.Order, то есть
	// в том, в котором и будут выполнены, а он содержательный — часть
	// подсистем обязана идти раньше других.
	kinds := map[string]string{
		"create": "создать",
		"update": "изменить",
		"delete": "удалить",
		"start":  "запустить",
		"stop":   "остановить",
	}
	disruptive := 0
	for _, a := range actions {
		mark := " "
		if a.Disruptive {
			mark = "!"
			disruptive++
		}
		kind := kinds[a.Kind]
		if kind == "" {
			kind = a.Kind
		}
		detail := ""
		if a.Detail != "" {
			detail = " — " + a.Detail
		}
		fmt.Printf(" %s %-12s %-10s %s%s\n", mark, a.Subsystem, kind, a.Target, detail)
	}

	fmt.Println()
	if disruptive > 0 {
		fmt.Printf("! — кратковременно прерывает связность (таких действий: %d)\n", disruptive)
	}
	fmt.Println("Применяются изменения из панели; netos restart приводит систему к конфигурации целиком.")
}

func printSummary(cfg *config.Config) {
	fmt.Println()
	fmt.Println("Конфигурация:")
	fmt.Printf("  Имя хоста:  %s\n", cfg.System.Hostname)
	fmt.Printf("  IPv6:       %s\n", cfg.IPv6.Mode)
	for _, w := range cfg.WANs {
		fmt.Printf("  Аплинк:     %s через %s (%s)\n", w.Name, w.Interface, w.Proto)
	}
	for _, n := range cfg.Networks {
		pool := "выключен"
		if n.DHCPPool.Enabled {
			pool = n.DHCPPool.Start + " – " + n.DHCPPool.End
		}
		fmt.Printf("  Сеть:       %s %s, DHCP: %s\n", n.Name, n.RouterAddress, pool)
	}
	fmt.Printf("  DHCP:       %s\n", cfg.DHCP.Provider)
	fmt.Printf("  DNS:        %s, порт %d\n", cfg.DNS.Provider, cfg.DNS.Port)
	fmt.Printf("  Панель:     порт %d\n", cfg.System.Panel.Port)
}

// stdLogger — журнал в стандартный log до появления полноценного.
type stdLogger struct{}

func (l *stdLogger) Infof(format string, args ...any)  { log.Printf("[инфо] "+format, args...) }
func (l *stdLogger) Warnf(format string, args ...any)  { log.Printf("[пред] "+format, args...) }
func (l *stdLogger) Errorf(format string, args ...any) { log.Printf("[ошиб] "+format, args...) }
