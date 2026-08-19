// Package sysctl настраивает параметры ядра, необходимые роутеру, и отдельной
// подсистемой подавляет IPv6.
package sysctl

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

const confPath = "/etc/sysctl.d/99-netos.conf"

// modulesPath заставляет ядро загрузить conntrack на загрузке.
//
// Без него systemd-sysctl на раннем этапе не находит
// net/netfilter/nf_conntrack_max: модуль подтягивается только вместе с первым
// правилом iptables, а это уже сильно позже. В журнале каждой загрузки
// оставалась ошибка, а размер таблицы до применения конфигурации netOS
// оставался стандартным — для роутера с десятками клиентов он мал.
const modulesPath = "/etc/modules-load.d/netos.conf"

const modulesData = "# Сгенерировано netOS. Правки будут перезаписаны.\nnf_conntrack\n"

// Core — базовые параметры ядра: форвардинг, conntrack, защита от спуфинга.
type Core struct {
	Runner system.Runner
}

func NewCore(r system.Runner) *Core { return &Core{Runner: r} }

func (c *Core) Name() string { return "sysctl" }

// values собирает нужные параметры. Держим их в одном месте, чтобы Plan и
// Apply не разъезжались.
func (c *Core) values(cfg *config.Config) map[string]string {
	v := map[string]string{
		// Без этого роутер не роутер.
		"net.ipv4.ip_forward": "1",

		// rp_filter в строгом режиме ломает policy-routing: ответный пакет,
		// пришедший через другой канал, будет отброшен как подделка. Ставим
		// нестрогий режим (2) — защита от очевидного спуфинга остаётся.
		"net.ipv4.conf.all.rp_filter":     "2",
		"net.ipv4.conf.default.rp_filter": "2",

		// Перенаправления ICMP на роутере не нужны и опасны.
		"net.ipv4.conf.all.accept_redirects":     "0",
		"net.ipv4.conf.default.accept_redirects": "0",
		"net.ipv4.conf.all.send_redirects":       "0",
		"net.ipv4.conf.default.send_redirects":   "0",
		"net.ipv4.conf.all.accept_source_route":  "0",

		"net.ipv4.tcp_syncookies":                    "1",
		"net.ipv4.icmp_echo_ignore_broadcasts":       "1",
		"net.ipv4.icmp_ignore_bogus_error_responses": "1",

		// Таблица conntrack по умолчанию мала для роутера с десятками клиентов.
		"net.netfilter.nf_conntrack_max": "131072",

		// Очередь для fq_codel и BBR: заметно лучше ведут себя на загруженном
		// аплинке, чем стандартный pfifo_fast с cubic.
		"net.core.default_qdisc":          "fq_codel",
		"net.ipv4.tcp_congestion_control": "bbr",
	}
	return v
}

func (c *Core) Plan(old, new *config.Config) ([]apply.Action, error) {
	desired := renderSysctl(c.values(new))
	current, _ := os.ReadFile(confPath)
	if string(current) == desired {
		return nil, nil
	}
	kind := "update"
	if len(current) == 0 {
		kind = "create"
	}
	return []apply.Action{{Kind: kind, Target: "параметры ядра", Detail: confPath}}, nil
}

func (c *Core) Apply(ctx context.Context, cfg *config.Config) error {
	if err := system.WriteFileAtomic(modulesPath, []byte(modulesData), 0o644); err != nil {
		return err
	}
	// Модуль нужен прямо сейчас: nf_conntrack_max появляется в /proc только
	// вместе с ним, а иначе значение из файла молча не применится. Отказ не
	// критичен — conntrack может быть собран в ядро, и тогда параметр уже на
	// месте.
	_, _ = c.Runner.Run(ctx, "modprobe", "nf_conntrack")

	data := renderSysctl(c.values(cfg))
	if err := system.WriteFileAtomic(confPath, []byte(data), 0o644); err != nil {
		return err
	}
	return applyFile(ctx, c.Runner, confPath)
}

func (c *Core) Health(ctx context.Context, cfg *config.Config) error {
	out, err := c.Runner.Run(ctx, "sysctl", "-n", "net.ipv4.ip_forward")
	if err != nil {
		return err
	}
	if strings.TrimSpace(out) != "1" {
		return fmt.Errorf("форвардинг IPv4 не включён")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Подавление IPv6
// ---------------------------------------------------------------------------

// IPv6 выключает IPv6 целиком. Это не косметика: клиент, привязанный к
// VPN-каналу политикой маршрутизации, при живом IPv6 пойдёт в интернет мимо
// туннеля — политики netOS работают только для IPv4.
type IPv6 struct {
	Runner system.Runner
}

func NewIPv6(r system.Runner) *IPv6 { return &IPv6{Runner: r} }

func (s *IPv6) Name() string { return "ipv6" }

const ipv6ConfPath = "/etc/sysctl.d/99-netos-ipv6.conf"

func (s *IPv6) values(cfg *config.Config) map[string]string {
	if cfg.IPv6.Mode != "off" {
		return map[string]string{
			"net.ipv6.conf.all.disable_ipv6":     "0",
			"net.ipv6.conf.default.disable_ipv6": "0",
			"net.ipv6.conf.all.accept_ra":        "1",
			"net.ipv6.conf.default.accept_ra":    "1",
			"net.ipv6.conf.all.autoconf":         "1",
			"net.ipv6.conf.default.autoconf":     "1",
			"net.ipv6.conf.all.forwarding":       "0",
		}
	}
	return map[string]string{
		"net.ipv6.conf.all.disable_ipv6":     "1",
		"net.ipv6.conf.default.disable_ipv6": "1",
		"net.ipv6.conf.lo.disable_ipv6":      "0", // ::1 нужен части системного софта
		"net.ipv6.conf.all.accept_ra":        "0",
		"net.ipv6.conf.default.accept_ra":    "0",
		"net.ipv6.conf.all.autoconf":         "0",
		"net.ipv6.conf.default.autoconf":     "0",
		"net.ipv6.conf.all.forwarding":       "0",
	}
}

func (s *IPv6) Plan(old, new *config.Config) ([]apply.Action, error) {
	if old != nil && old.IPv6.Mode == new.IPv6.Mode {
		return nil, nil
	}
	detail := "IPv6 отключается на всех интерфейсах"
	if new.IPv6.Mode != "off" {
		detail = "IPv6 включается обратно"
	}
	return []apply.Action{{
		Kind:       "update",
		Target:     "IPv6",
		Detail:     detail,
		Disruptive: true,
	}}, nil
}

func (s *IPv6) Apply(ctx context.Context, cfg *config.Config) error {
	data := renderSysctl(s.values(cfg))
	if err := system.WriteFileAtomic(ipv6ConfPath, []byte(data), 0o644); err != nil {
		return err
	}
	if err := applyFile(ctx, s.Runner, ipv6ConfPath); err != nil {
		return err
	}

	// Параметры all/default действуют на интерфейсы, созданные позже, но уже
	// поднятые интерфейсы их не всегда подхватывают — проходим по ним отдельно.
	names, err := interfaceNames()
	if err != nil {
		return err
	}
	for _, name := range names {
		if name == "lo" {
			continue
		}
		// accept_ra и autoconf гасятся вместе с disable_ipv6, а не полагаются
		// на него. Значения all/default подхватываются только новыми
		// интерфейсами, и на уже поднятом линке их переписывает кто угодно:
		// на облачных образах это делает tuned, о чём systemd-networkd честно
		// сообщает в журнал. Пока IPv6 выключен, это безвредно, но стоит
		// включить его режим — и роутер получил бы маршруты из чужих RA.
		values := map[string]string{"disable_ipv6": "1", "accept_ra": "0", "autoconf": "0"}
		if cfg.IPv6.Mode != "off" {
			values = map[string]string{"disable_ipv6": "0", "accept_ra": "1", "autoconf": "1"}
		}
		for key, value := range values {
			setting := fmt.Sprintf("net.ipv6.conf.%s.%s=%s", name, key, value)
			// Ошибку игнорируем: интерфейс мог исчезнуть между чтением и записью.
			_, _ = s.Runner.Run(ctx, "sysctl", "-q", "-w", setting)
		}
	}
	return nil
}

func (s *IPv6) Health(ctx context.Context, cfg *config.Config) error {
	out, err := s.Runner.Run(ctx, "sysctl", "-n", "net.ipv6.conf.all.disable_ipv6")
	if err != nil {
		// Ядро может быть собрано вовсе без IPv6 — тогда и подавлять нечего.
		return nil
	}
	want := "1"
	if cfg.IPv6.Mode != "off" {
		want = "0"
	}
	if strings.TrimSpace(out) != want {
		return fmt.Errorf("режим IPv6 не применён")
	}
	return nil
}

// ---------------------------------------------------------------------------

func renderSysctl(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sortStrings(keys)

	var b strings.Builder
	b.WriteString("# Сгенерировано netOS. Правки будут перезаписаны.\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s = %s\n", k, values[k])
	}
	return b.String()
}

// applyFile загружает файл параметров. Часть ключей может отсутствовать
// (например, nf_conntrack_max до загрузки модуля), поэтому единичные ошибки
// не считаем фатальными — они пишутся в вывод и видны в журнале.
func applyFile(ctx context.Context, r system.Runner, path string) error {
	_, err := r.Run(ctx, "sysctl", "-q", "-p", path)
	if err != nil && !strings.Contains(err.Error(), "No such file or directory") {
		return err
	}
	return nil
}

func interfaceNames() ([]string, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, filepath.Base(e.Name()))
	}
	return names, nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
