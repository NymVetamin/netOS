// Package routing управляет таблицами маршрутизации, статическими маршрутами
// и правилами выбора таблиц.
//
// Это фундамент для выбора канала под каждого клиента: канал получает
// собственную таблицу с маршрутом по умолчанию через свой туннель, а правило
// направляет в неё помеченный трафик. Пока каналов нет, тот же механизм
// доступен администратору напрямую.
package routing

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// Файл с именами таблиц. Именованные таблицы удобнее номеров: команда
// ip route show table netos-vpn читается без сверки с документацией.
const rtTablesPath = "/etc/iproute2/rt_tables.d/netos.conf"

// Собственный протокол маршрутов. Благодаря ему в выводе ip route видно, что
// маршрут поставил netOS, а не ядро и не клиент DHCP, — и его же используем,
// чтобы отличать свои маршруты от чужих при уборке.
//
// Пользовательские статические маршруты помечаются штатным proto static,
// маршруты аплинков — netos: так подсистемы не удаляют работу друг друга.
const rtProtosPath = "/etc/iproute2/rt_protos.d/netos.conf"

// Приоритеты правил netOS занимают отдельный диапазон, чтобы не спорить с
// правилами системы (0, 32766, 32767) и оставить место для ручных.
const (
	rulePriorityBase = 20000
	rulePriorityMax  = 29999
)

type Subsystem struct {
	Runner system.Runner
}

func New(r system.Runner) *Subsystem { return &Subsystem{Runner: r} }

func (s *Subsystem) Name() string { return "routing" }

func (s *Subsystem) Plan(old, new *config.Config) ([]apply.Action, error) {
	var actions []apply.Action

	if old == nil {
		if n := len(enabledRoutes(new)); n > 0 {
			actions = append(actions, apply.Action{
				Kind: "create", Target: "статические маршруты", Detail: fmt.Sprintf("%d шт.", n),
			})
		}
		if n := len(enabledRules(new)); n > 0 {
			actions = append(actions, apply.Action{
				Kind: "create", Target: "правила маршрутизации", Detail: fmt.Sprintf("%d шт.", n),
			})
		}
		return actions, nil
	}

	if !reflect.DeepEqual(old.Routing.Tables, new.Routing.Tables) {
		actions = append(actions, apply.Action{Kind: "update", Target: "таблицы маршрутизации"})
	}
	if !reflect.DeepEqual(enabledRoutes(old), enabledRoutes(new)) {
		actions = append(actions, apply.Action{Kind: "update", Target: "статические маршруты"})
	}
	if !reflect.DeepEqual(enabledRules(old), enabledRules(new)) {
		actions = append(actions, apply.Action{
			Kind: "update", Target: "правила маршрутизации", Disruptive: true,
		})
	}
	return actions, nil
}

func (s *Subsystem) Apply(ctx context.Context, cfg *config.Config) error {
	if err := s.writeProtos(); err != nil {
		return err
	}
	if err := s.writeTables(cfg); err != nil {
		return err
	}
	if err := s.applyRoutes(ctx, cfg); err != nil {
		return err
	}
	return s.applyRules(ctx, cfg)
}

// writeTables регистрирует имена таблиц, чтобы к ним можно было обращаться по
// имени и в командах netOS, и вручную из консоли.
func (s *Subsystem) writeTables(cfg *config.Config) error {
	var b strings.Builder
	b.WriteString("# Сгенерировано netOS. Правки будут перезаписаны.\n")
	for _, t := range cfg.Routing.Tables {
		fmt.Fprintf(&b, "%d\t%s\n", t.Number, t.Name)
	}
	return system.WriteFileAtomic(rtTablesPath, []byte(b.String()), 0o644)
}

// writeProtos регистрирует имя протокола, чтобы ip route показывал proto netos
// вместо голого номера.
func (s *Subsystem) writeProtos() error {
	var b strings.Builder
	b.WriteString("# Сгенерировано netOS. Правки будут перезаписаны.\n")
	fmt.Fprintf(&b, "%d\t%s\n", config.RouteProto, config.RouteProtoName)
	return system.WriteFileAtomic(rtProtosPath, []byte(b.String()), 0o644)
}

// applyRoutes приводит статические маршруты к описанному виду.
//
// netOS владеет полным набором статических маршрутов. Маршруты ядра, DHCP и
// других динамических протоколов не затрагиваются.
func (s *Subsystem) applyRoutes(ctx context.Context, cfg *config.Config) error {
	wanted := map[string]bool{}
	for _, r := range enabledRoutes(cfg) {
		wanted[staticRouteKey(r)] = true
	}

	// table all находит хвосты даже в таблицах, уже удалённых из конфигурации.
	out, err := s.Runner.Run(ctx, "ip", "-4", "route", "show", "table", "all",
		"proto", "static")
	if err != nil {
		return fmt.Errorf("чтение статических маршрутов netOS: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || wanted[routeLineKey(line)] {
			continue
		}
		args := append([]string{"-4", "route", "del"}, strings.Fields(line)...)
		if _, err := s.Runner.Run(ctx, "ip", args...); err != nil {
			return fmt.Errorf("удаление старого маршрута %q: %w", line, err)
		}
	}

	for _, r := range enabledRoutes(cfg) {
		args := []string{"-4", "route", "replace"}

		switch r.Type {
		case "blackhole", "unreachable", "prohibit":
			args = append(args, r.Type, r.Destination)
		default:
			args = append(args, r.Destination)
			if r.Gateway != "" {
				args = append(args, "via", r.Gateway)
			}
			if r.Interface != "" {
				args = append(args, "dev", r.Interface)
			}
		}
		if r.Metric > 0 {
			args = append(args, "metric", fmt.Sprint(r.Metric))
		}
		if r.Table != "" {
			args = append(args, "table", r.Table)
		}
		args = append(args, "proto", "static")

		if _, err := s.Runner.Run(ctx, "ip", args...); err != nil {
			return fmt.Errorf("маршрут %s: %w", r.Destination, err)
		}
	}
	return nil
}

func routeKey(table, destination, routeType, gateway, iface string, metric int) string {
	if table == "main" {
		table = ""
	}
	if routeType == "" {
		routeType = "unicast"
	}
	return fmt.Sprintf("%s|%s|%s|%s|%s|%d", table, destination, routeType, gateway, iface, metric)
}

func staticRouteKey(r config.StaticRoute) string {
	return routeKey(r.Table, r.Destination, r.Type, r.Gateway, r.Interface, r.Metric)
}

func routeLineKey(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	destination := fields[0]
	routeType := "unicast"
	if (destination == "blackhole" || destination == "unreachable" || destination == "prohibit") && len(fields) > 1 {
		routeType = destination
		destination = fields[1]
	}
	table, gateway, iface, metric := "", "", "", 0
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "table":
			table = fields[i+1]
		case "via":
			gateway = fields[i+1]
		case "dev":
			iface = fields[i+1]
		case "metric":
			_, _ = fmt.Sscan(fields[i+1], &metric)
		}
	}
	return routeKey(table, destination, routeType, gateway, iface, metric)
}

// applyRules пересобирает правила выбора таблиц.
//
// Правила снимаются и ставятся заново целиком: их немного, а вычислять
// разницу для команды, у которой нет replace, дороже и рискованнее, чем
// пересоздать набор.
func (s *Subsystem) applyRules(ctx context.Context, cfg *config.Config) error {
	out, err := s.Runner.Run(ctx, "ip", "-4", "rule", "show")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(out, "\n") {
		prio := leadingPriority(line)
		if prio < rulePriorityBase || prio > rulePriorityMax {
			continue
		}
		_, _ = s.Runner.Run(ctx, "ip", "-4", "rule", "del", "priority", fmt.Sprint(prio))
	}

	for _, r := range enabledRules(cfg) {
		args := []string{"-4", "rule", "add"}
		if r.From != "" {
			args = append(args, "from", r.From)
		} else {
			args = append(args, "from", "all")
		}
		if r.To != "" {
			args = append(args, "to", r.To)
		}
		if r.FwMark != "" {
			args = append(args, "fwmark", r.FwMark)
		}
		if r.Interface != "" {
			args = append(args, "iif", r.Interface)
		}
		priority := r.Priority
		if priority < rulePriorityBase || priority > rulePriorityMax {
			priority = rulePriorityBase + 100
		}
		args = append(args, "priority", fmt.Sprint(priority), "lookup", r.Table)

		if _, err := s.Runner.Run(ctx, "ip", args...); err != nil {
			return fmt.Errorf("правило маршрутизации %s: %w", r.Name, err)
		}
	}
	return nil
}

func (s *Subsystem) Health(ctx context.Context, cfg *config.Config) error {
	if len(enabledRules(cfg)) == 0 {
		return nil
	}
	out, err := s.Runner.Run(ctx, "ip", "-4", "rule", "show")
	if err != nil {
		return err
	}
	for _, r := range enabledRules(cfg) {
		if !strings.Contains(out, r.Table) {
			return fmt.Errorf("правило для таблицы %s не применилось", r.Table)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------

func enabledRoutes(cfg *config.Config) []config.StaticRoute {
	var out []config.StaticRoute
	for _, r := range cfg.Routing.Static {
		if r.Enabled {
			out = append(out, r)
		}
	}
	return out
}

func enabledRules(cfg *config.Config) []config.RouteRule {
	var out []config.RouteRule
	for _, r := range cfg.Routing.Rules {
		if r.Enabled && r.Table != "" {
			out = append(out, r)
		}
	}
	return out
}

// leadingPriority вытаскивает приоритет из строки вида "20100: from all ...".
func leadingPriority(line string) int {
	line = strings.TrimSpace(line)
	idx := strings.IndexByte(line, ':')
	if idx <= 0 {
		return -1
	}
	n := 0
	for _, ch := range line[:idx] {
		if ch < '0' || ch > '9' {
			return -1
		}
		n = n*10 + int(ch-'0')
	}
	return n
}
