package firewall

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

// Subsystem применяет правила файрволла.
type Subsystem struct {
	Runner   system.Runner
	StateDir string // куда складывать сгенерированные ruleset'ы
	// Legacy заставляет использовать iptables-legacy вместо стандартного
	// iptables-nft. На системах, где часть правил ставит кто-то ещё через
	// nft, смешивать бэкенды нельзя, и выбор остаётся за администратором.
	Legacy bool
}

func New(r system.Runner, stateDir string) *Subsystem {
	return &Subsystem{Runner: r, StateDir: stateDir}
}

func (s *Subsystem) Name() string { return "firewall" }

func (s *Subsystem) restoreCmd() string {
	if s.Legacy {
		return "iptables-legacy-restore"
	}
	return "iptables-restore"
}

func (s *Subsystem) restore6Cmd() string {
	if s.Legacy {
		return "ip6tables-legacy-restore"
	}
	return "ip6tables-restore"
}

// Plan сравнивает сгенерированный ruleset с применённым и показывает, что
// изменится. Диффа по строкам достаточно: правила детерминированы, порядок
// стабилен, поэтому изменение в UI даёт минимальный дифф в плане.
func (s *Subsystem) Plan(old, new *config.Config) ([]apply.Action, error) {
	newRS, err := Build(new)
	if err != nil {
		return nil, err
	}
	if old == nil {
		return []apply.Action{{
			Kind:   "create",
			Target: "iptables",
			Detail: fmt.Sprintf("установка %d правил", countRules(newRS.IPv4)),
		}}, nil
	}
	oldRS, err := Build(old)
	if err != nil {
		return nil, err
	}
	var actions []apply.Action
	if oldRS.IPv4 != newRS.IPv4 {
		added, removed := diffCount(oldRS.IPv4, newRS.IPv4)
		actions = append(actions, apply.Action{
			Kind:   "update",
			Target: "iptables",
			Detail: fmt.Sprintf("+%d правил, -%d правил", added, removed),
		})
	}
	if oldRS.IPv6 != newRS.IPv6 {
		detail := "обновление блокировки IPv6"
		if new.IPv6.Mode != "off" {
			detail = "снятие блокировки IPv6"
		}
		actions = append(actions, apply.Action{Kind: "update", Target: "ip6tables", Detail: detail})
	}
	return actions, nil
}

func (s *Subsystem) Apply(ctx context.Context, cfg *config.Config) error {
	rs, err := Build(cfg)
	if err != nil {
		return err
	}

	// Сохраняем ruleset на диск: он нужен для отладки, для показа в панели
	// и для восстановления правил при загрузке до старта netosd.
	path := filepath.Join(s.StateDir, "iptables.rules")
	if err := system.WriteFileAtomic(path, []byte(rs.IPv4), 0o600); err != nil {
		return fmt.Errorf("сохранение ruleset: %w", err)
	}

	if _, err := s.Runner.RunInput(ctx, rs.IPv4, s.restoreCmd()); err != nil {
		return fmt.Errorf("применение правил iptables: %w", err)
	}

	path6 := filepath.Join(s.StateDir, "ip6tables.rules")
	if err := system.WriteFileAtomic(path6, []byte(rs.IPv6), 0o600); err != nil {
		return fmt.Errorf("сохранение ruleset IPv6: %w", err)
	}
	if _, err := s.Runner.RunInput(ctx, rs.IPv6, s.restore6Cmd()); err != nil {
		// Ядро может быть собрано без IPv6 вовсе — тогда блокировать нечего.
		if !strings.Contains(err.Error(), "does not exist") {
			return fmt.Errorf("применение правил ip6tables: %w", err)
		}
	}

	return nil
}

// Health проверяет, что цепочки netOS действительно на месте. Если что-то
// сбросило правила между применением и проверкой, лучше узнать об этом сразу
// и откатиться, чем оставить роутер с политикой DROP и без разрешающих правил.
func (s *Subsystem) Health(ctx context.Context, cfg *config.Config) error {
	if !cfg.Firewall.Enabled {
		return nil
	}
	save := "iptables-save"
	if s.Legacy {
		save = "iptables-legacy-save"
	}
	out, err := s.Runner.Run(ctx, save)
	if err != nil {
		return fmt.Errorf("чтение текущих правил: %w", err)
	}
	// Проверяем ровно те цепочки, которые генератор должен был создать: зона
	// без интерфейсов цепочек не получает, и требовать их наличия нельзя.
	for _, chain := range ExpectedChains(cfg) {
		if !strings.Contains(out, ":"+chain) {
			return fmt.Errorf("цепочка %s отсутствует после применения", chain)
		}
	}
	return nil
}

// RestoreOnBoot возвращает содержимое ruleset'а, сохранённого при последнем
// применении. Используется юнитом, который поднимает правила до старта сети,
// чтобы между загрузкой и стартом netosd не было окна без файрволла.
func (s *Subsystem) RestoreOnBoot() ([]byte, error) {
	return os.ReadFile(filepath.Join(s.StateDir, "iptables.rules"))
}

func countRules(ruleset string) int {
	n := 0
	for _, line := range strings.Split(ruleset, "\n") {
		if strings.HasPrefix(line, "-A ") {
			n++
		}
	}
	return n
}

func diffCount(old, new string) (added, removed int) {
	oldSet := map[string]bool{}
	for _, line := range strings.Split(old, "\n") {
		if strings.HasPrefix(line, "-A ") {
			oldSet[line] = true
		}
	}
	newSet := map[string]bool{}
	for _, line := range strings.Split(new, "\n") {
		if strings.HasPrefix(line, "-A ") {
			newSet[line] = true
			if !oldSet[line] {
				added++
			}
		}
	}
	for line := range oldSet {
		if !newSet[line] {
			removed++
		}
	}
	return added, removed
}
