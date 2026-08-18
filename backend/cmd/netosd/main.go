// Команда netosd — демон netOS: применяет конфигурацию и обслуживает
// веб-панель.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/netos-router/netos/internal/api"
	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/bootstrap"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/runtime"
	"github.com/netos-router/netos/internal/store"
	"github.com/netos-router/netos/internal/subsys/components"
	"github.com/netos-router/netos/internal/subsys/firewall"
	"github.com/netos-router/netos/internal/subsys/hostsettings"
	"github.com/netos-router/netos/internal/subsys/netiface"
	"github.com/netos-router/netos/internal/subsys/routing"
	"github.com/netos-router/netos/internal/subsys/services"
	"github.com/netos-router/netos/internal/subsys/sysctl"
	"github.com/netos-router/netos/internal/system"
)

const (
	stateDir = "/var/lib/netos/generated"
	// credentialsPath — файл с учётными данными первого запуска. Установщик
	// читает его вместо разбора журнала: журнал хранит записи прошлых
	// установок, и вытащить из него именно текущий пароль надёжно нельзя.
	// Файл удаляется, как только администратор сменит пароль.
	credentialsPath = "/var/lib/netos/initial-credentials"
	tlsDir          = "/etc/netos/tls"
	leasePath       = "/var/lib/netos/dnsmasq.leases"
)

func main() {
	var (
		dbPath   = flag.String("db", "/var/lib/netos/netos.db", "путь к базе данных")
		dryRun   = flag.Bool("dry-run", false, "показать действия, ничего не применяя")
		verbose  = flag.Bool("v", false, "подробный журнал выполняемых команд")
		showPlan = flag.Bool("plan", false, "показать план применения и выйти")
		render   = flag.String("render", "", "напечатать сгенерированный артефакт (iptables|dnsmasq|config) и выйти")
		initOnly = flag.Bool("init", false, "создать стартовую конфигурацию и выйти")
		applyNow = flag.Bool("apply", false, "применить активную конфигурацию и выйти")
	)
	flag.Parse()

	logger := &stdLogger{}
	runner := system.NewExec()
	if *verbose {
		runner.OnCommand = func(name string, args []string) {
			log.Printf("  $ %s %v", name, args)
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

	if *initOnly {
		fmt.Printf("Стартовая конфигурация создана, ревизия %d\n", revID)
		printSummary(cfg)
		return
	}

	engine := apply.NewEngine(logger, *dryRun)
	if err := registerSubsystems(engine, runner, logger); err != nil {
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
		actions, err := engine.Plan(cfg)
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
	if _, err := engine.Apply(ctx, cfg, revID, false); err != nil {
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

	// Первый запуск: заводим администратора и печатаем учётные данные.
	// Дальше пароль знает только владелец машины.
	if err := ensureAdmin(st, cfg, logger); err != nil {
		log.Fatalf("не удалось создать учётную запись администратора: %v", err)
	}

	collector := runtime.NewCollector(runner, leasePath)
	panel := api.New(st, engine, collector, logger)

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

// ensureAdmin создаёт учётную запись при первом запуске и печатает пароль в
// журнал: это единственный момент, когда он виден открытым текстом.
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
	if _, err := st.CreateUser("admin", hash, "admin", true); err != nil {
		return err
	}

	addrs := panelAddresses(cfg)
	fmt.Println()
	fmt.Println("==============================================================")
	fmt.Println("  netOS готов к работе")
	fmt.Println()
	port := strconv.Itoa(cfg.System.Panel.Port)
	for i, a := range addrs {
		label := "  Адрес панели:  "
		if i > 0 {
			label = "                 "
		}
		fmt.Println(label + "https://" + a + ":" + port)
	}
	fmt.Println("  Пользователь:  admin")
	fmt.Println("  Пароль:        " + password)
	fmt.Println()
	fmt.Println("  Пароль потребуется сменить при первом входе.")
	fmt.Println("  Сертификат самоподписанный — браузер предупредит об этом.")
	fmt.Println("==============================================================")
	fmt.Println()

	if err := writeCredentials(addrs, cfg.System.Panel.Port, password); err != nil {
		logger.Warnf("не удалось сохранить файл с учётными данными: %v", err)
	}

	logger.Infof("создана учётная запись admin, пароль напечатан выше")
	return nil
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
	}

	logger.Infof("конфигурации нет, определяю параметры машины")
	detected, err := bootstrap.Detect(ctx, runner)
	if err != nil {
		return nil, 0, fmt.Errorf("определение параметров: %w", err)
	}
	logger.Infof("аплинк: %s (%s), свободные интерфейсы: %v",
		detected.WANInterface, detected.WANAddress, detected.LANCandidates)

	cfg := bootstrap.BuildInitial(detected)
	id, err := st.CreateRevision(cfg, "system", "стартовая конфигурация")
	if err != nil {
		return nil, 0, err
	}
	return cfg, id, nil
}

func registerSubsystems(engine *apply.Engine, runner system.Runner, logger apply.Logger) error {
	svc := services.NewManager(runner)

	subsystems := []apply.Subsystem{
		components.New(runner, logger),
		hostsettings.New(runner),
		sysctl.NewCore(runner),
		sysctl.NewIPv6(runner),
		netiface.NewInterfaces(runner),
		netiface.NewNetworks(runner),
		netiface.NewWAN(runner),
		routing.New(runner),
		firewall.New(runner, stateDir),
		services.NewDHCP(svc),
		services.NewDNS(svc),
	}
	for _, s := range subsystems {
		if err := engine.Register(s); err != nil {
			return err
		}
	}
	return nil
}

func renderArtifact(kind string, cfg *config.Config) error {
	switch kind {
	case "iptables":
		rs, err := firewall.Build(cfg)
		if err != nil {
			return err
		}
		fmt.Print(rs.IPv4)
		if rs.IPv6 != "" {
			fmt.Println("\n# --- ip6tables ---")
			fmt.Print(rs.IPv6)
		}
	case "dnsmasq":
		d := services.NewDnsmasq(nil)
		fmt.Print(d.Render(cfg))
	case "config":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(cfg)
	default:
		return fmt.Errorf("неизвестный артефакт %q (доступны: iptables, dnsmasq, config)", kind)
	}
	return nil
}

func printPlan(actions []apply.Action) {
	if len(actions) == 0 {
		fmt.Println("Изменений нет: система уже соответствует конфигурации.")
		return
	}
	fmt.Printf("Запланировано действий: %d\n\n", len(actions))
	for _, a := range actions {
		mark := " "
		if a.Disruptive {
			mark = "!"
		}
		detail := ""
		if a.Detail != "" {
			detail = " — " + a.Detail
		}
		fmt.Printf(" %s [%-10s] %-8s %s%s\n", mark, a.Subsystem, a.Kind, a.Target, detail)
	}
	fmt.Println("\n! — действие кратковременно прерывает связность")
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
