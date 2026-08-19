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

// setting — один параметр ядра с объяснением, зачем он такой.
//
// Пояснения попадают в сгенерированный файл. Администратор рано или поздно
// заглядывает в /etc/sysctl.d, и «откуда здесь это значение» — первый вопрос,
// который у него возникает; отвечать на него в документации, лежащей в другом
// месте, поздно.
type setting struct {
	key     string
	value   string
	comment string
}

// group — раздел сгенерированного файла.
type group struct {
	title    string
	settings []setting
}

// coreGroups перечисляет параметры ядра в том виде, в каком они попадут в файл.
//
// Порядок и группировка заданы явно, а не сортировкой: список читают глазами, и
// форвардинг рядом с размерами буферов TCP только мешает. Plan, Apply и
// netos render sysctl берут его отсюда, поэтому разъехаться им негде.
func coreGroups(cfg *config.Config) []group {
	return []group{
		{
			title: "Маршрутизация",
			settings: []setting{
				{"net.ipv4.ip_forward", "1", "без этого роутер не роутер"},
				{"net.ipv4.conf.all.rp_filter", "2",
					"нестрогая проверка обратного пути: строгая ломает policy-routing —\n" +
						"ответный пакет, пришедший через другой канал, отбрасывался бы как подделка"},
				{"net.ipv4.conf.default.rp_filter", "2", ""},
			},
		},
		{
			title: "Защита",
			settings: []setting{
				{"net.ipv4.conf.all.accept_redirects", "0", "перенаправления ICMP роутеру не нужны и опасны"},
				{"net.ipv4.conf.default.accept_redirects", "0", ""},
				{"net.ipv4.conf.all.send_redirects", "0", ""},
				{"net.ipv4.conf.default.send_redirects", "0", ""},
				{"net.ipv4.conf.all.accept_source_route", "0", ""},
				{"net.ipv4.tcp_syncookies", "1", ""},
				{"net.ipv4.icmp_echo_ignore_broadcasts", "1", ""},
				{"net.ipv4.icmp_ignore_bogus_error_responses", "1", ""},
			},
		},
		{
			title: "Таблица соединений",
			settings: []setting{
				{"net.netfilter.nf_conntrack_max", "131072",
					"значение по умолчанию мало для роутера с десятками клиентов"},
			},
		},
		{
			title: "Управление перегрузкой",
			settings: []setting{
				{"net.core.default_qdisc", "fq_codel",
					"именно fq_codel, а не fq: на аплинке роутера главная беда — раздутые\n" +
						"очереди у провайдера, и codel борется с ними, а fq только распределяет"},
				{"net.ipv4.tcp_congestion_control", "bbr",
					"на канале с большим RTT и потерями заметно лучше cubic"},
				{"net.ipv4.tcp_slow_start_after_idle", "0",
					"иначе после паузы соединение каждый раз разгоняется заново"},
				{"net.ipv4.tcp_mtu_probing", "1",
					"под PPPoE и туннелями MTU меньше 1500, а ICMP по дороге часто режут"},
				{"net.ipv4.tcp_fastopen", "3", ""},
			},
		},
		{
			title: "Буферы и очереди",
			settings: []setting{
				{"net.core.rmem_max", "16777216",
					"буферы влияют на соединения самого роутера — панель, DNS, туннели, —\n" +
						"а не на транзитный трафик: тот через сокеты не проходит"},
				{"net.core.wmem_max", "16777216", ""},
				{"net.ipv4.tcp_rmem", "4096 262144 16777216", ""},
				{"net.ipv4.tcp_wmem", "4096 262144 16777216", ""},
				{"net.core.netdev_max_backlog", "16384",
					"очередь пакетов, принятых картой, но ещё не разобранных ядром"},
				{"net.core.somaxconn", "4096", ""},
				{"net.ipv4.tcp_max_syn_backlog", "8192", ""},
			},
		},
		{
			title: "Таймауты и порты",
			settings: []setting{
				{"net.ipv4.tcp_keepalive_time", "1200", ""},
				{"net.ipv4.tcp_keepalive_probes", "5", ""},
				{"net.ipv4.tcp_keepalive_intvl", "30", ""},
				{"net.ipv4.tcp_fin_timeout", "30", ""},
				{"net.ipv4.tcp_tw_reuse", "1", ""},
				{"net.ipv4.ip_local_port_range", "10240 60999",
					"диапазон расширен, но начинается не с 1024: из него же netfilter берёт\n" +
						"порт при маскараде, и заход на 1024 столкнул бы NAT с портом панели"},
			},
		},
	}
}

// values собирает параметры для применения. Держим их в одном месте, чтобы
// Plan и Apply не разъезжались.
func (c *Core) values(cfg *config.Config) map[string]string {
	v := map[string]string{}
	for _, g := range coreGroups(cfg) {
		for _, s := range g.settings {
			v[s.key] = s.value
		}
	}
	return v
}

func (c *Core) Plan(old, new *config.Config) ([]apply.Action, error) {
	desired := renderGroups(coreGroups(new))
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

	data := renderGroups(coreGroups(cfg))
	if err := system.WriteFileAtomic(confPath, []byte(data), 0o644); err != nil {
		return err
	}
	return applyValues(c.values(cfg))
}

func (c *Core) Health(ctx context.Context, cfg *config.Config) error {
	out, err := readSysctl("net.ipv4.ip_forward")
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
	if err := applyValues(s.values(cfg)); err != nil {
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
			// Ошибку игнорируем: интерфейс мог исчезнуть между чтением и записью.
			_ = writeSysctl("net.ipv6.conf."+name+"."+key, value)
		}
	}
	return nil
}

func (s *IPv6) Health(ctx context.Context, cfg *config.Config) error {
	out, err := readSysctl("net.ipv6.conf.all.disable_ipv6")
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

// Render печатает все параметры ядра, которыми управляет netOS, вместе с тем,
// в какой файл каждый из них попадает.
//
// Отдельная команда нужна потому, что параметры разложены по двум файлам в
// /etc/sysctl.d, а вопрос у администратора один: что netOS сделал с ядром.
// Править /etc/sysctl.conf netOS не станет — это файл чужого пакета, и уборка
// за собой при удалении из него была бы ненадёжной, — но показать всё сразу
// обязан.
func Render(cfg *config.Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n", confPath)
	b.WriteString(renderGroups(coreGroups(cfg)))
	b.WriteString("\n")
	fmt.Fprintf(&b, "# %s\n", ipv6ConfPath)
	b.WriteString(renderSysctl((&IPv6{}).values(cfg)))
	b.WriteString("\n")
	fmt.Fprintf(&b, "# %s\n", modulesPath)
	b.WriteString(modulesData)
	return b.String()
}

// renderGroups собирает файл из разделов с пояснениями.
func renderGroups(groups []group) string {
	var b strings.Builder
	b.WriteString("# Сгенерировано netOS. Правки будут перезаписаны.\n")
	b.WriteString("#\n")
	b.WriteString("# Это полный список параметров ядра, которыми управляет netOS.\n")
	b.WriteString("# Показать его целиком, вместе с параметрами IPv6: netos render sysctl\n")
	for _, g := range groups {
		fmt.Fprintf(&b, "\n# ===== %s =====\n", g.title)
		for _, st := range g.settings {
			if st.comment != "" {
				for _, line := range strings.Split(st.comment, "\n") {
					fmt.Fprintf(&b, "# %s\n", line)
				}
			}
			fmt.Fprintf(&b, "%s = %s\n", st.key, st.value)
		}
	}
	return b.String()
}

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

// applyValues проставляет параметры ядра напрямую через /proc/sys.
//
// Внешний sysctl намеренно не используется. Он живёт в пакете procps, которого
// на минимальной установке Debian просто нет: netosd падал на первом же
// применении с «executable file not found» и уходил в цикл перезапусков. На
// облачных образах procps стоит всегда, поэтому промах не был виден до
// проверки на чистой системе.
//
// Прямая запись заодно точнее: мы знаем, какие именно ключи нам принадлежат, и
// не зависим от того, как та или иная версия sysctl разбирает файл.
//
// Отсутствующий ключ — не ошибка: nf_conntrack_max появляется только вместе с
// модулем, а в контейнере часть параметров не существует вовсе. Молчать про
// такое можно: файл в /etc/sysctl.d остаётся и подействует, когда ключ
// появится.
func applyValues(values map[string]string) error {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sortStrings(keys)

	for _, key := range keys {
		if err := writeSysctl(key, values[key]); err != nil {
			return fmt.Errorf("параметр %s: %w", key, err)
		}
	}
	return nil
}

// writeSysctl переводит имя параметра в путь внутри /proc/sys и записывает
// значение.
func writeSysctl(key, value string) error {
	path := filepath.Join("/proc/sys", filepath.Join(strings.Split(key, ".")...))
	err := os.WriteFile(path, []byte(value), 0o644)
	switch {
	case err == nil:
		return nil
	case os.IsNotExist(err):
		// Ключа в этом ядре нет.
		return nil
	case os.IsPermission(err):
		// Параметр есть, но пространство имён его не отдаёт — так ведут себя
		// контейнеры. Роутеру это не мешает: там, где netOS хозяин, права есть.
		return nil
	default:
		return err
	}
}

// readSysctl читает значение параметра из /proc/sys.
func readSysctl(key string) (string, error) {
	path := filepath.Join("/proc/sys", filepath.Join(strings.Split(key, ".")...))
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
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
