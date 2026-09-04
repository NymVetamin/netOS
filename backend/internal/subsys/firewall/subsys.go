package firewall

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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
	return s.PlanContext(context.Background(), old, new)
}

func (s *Subsystem) PlanContext(ctx context.Context, old, new *config.Config) ([]apply.Action, error) {
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
	if len(actions) == 0 {
		ipv4OK, ipv6OK, err := s.liveMatches(ctx, newRS)
		if err != nil {
			return nil, err
		}
		if !ipv4OK {
			actions = append(actions, apply.Action{Kind: "update", Target: "iptables", Detail: "исправление расхождения с живыми правилами"})
		}
		if !ipv6OK {
			actions = append(actions, apply.Action{Kind: "update", Target: "ip6tables", Detail: "исправление расхождения с живыми правилами IPv6"})
		}
	}
	return actions, nil
}

func (s *Subsystem) Apply(ctx context.Context, cfg *config.Config) error {
	rs, err := Build(cfg)
	if err != nil {
		return err
	}
	path := filepath.Join(s.StateDir, "iptables.rules")
	path6 := filepath.Join(s.StateDir, "ip6tables.rules")
	previousLive, err := s.snapshotLive(ctx)
	if err != nil {
		return err
	}
	ipv4OK := rulesetMatches(previousLive.ipv4, rs.IPv4)
	ipv6OK := previousLive.ipv6Missing || rulesetMatches(previousLive.ipv6, rs.IPv6)
	state4OK := rulesetFileReady(path, []byte(rs.IPv4))
	state6OK := rulesetFileReady(path6, []byte(rs.IPv6))
	if ipv4OK && ipv6OK && state4OK && state6OK {
		return nil
	}
	if ipv4OK && ipv6OK {
		return persistRulesetPair(path, []byte(rs.IPv4), path6, []byte(rs.IPv6))
	}
	if _, err := s.Runner.RunInput(ctx, rs.IPv4, s.restoreCmd(), "--test"); err != nil {
		return fmt.Errorf("проверка правил iptables: %w", err)
	}
	if _, err := s.Runner.RunInput(ctx, rs.IPv6, s.restore6Cmd(), "--test"); err != nil && !missingIPv6Tables(err) {
		return fmt.Errorf("проверка правил ip6tables: %w", err)
	}

	// Сохраняем ruleset на диск: он нужен для отладки, для показа в панели
	// и для восстановления правил при загрузке до старта netosd.
	previous4, err := snapshotRuleset(path)
	if err != nil {
		return fmt.Errorf("чтение предыдущего ruleset: %w", err)
	}
	previous6, err := snapshotRuleset(path6)
	if err != nil {
		return fmt.Errorf("чтение предыдущего ruleset IPv6: %w", err)
	}
	if err := system.WriteFileAtomic(path, []byte(rs.IPv4), 0o600); err != nil {
		return fmt.Errorf("сохранение ruleset: %w", err)
	}
	if err := system.WriteFileAtomic(path6, []byte(rs.IPv6), 0o600); err != nil {
		restoreErr := restoreRulesetSnapshot(previous4)
		return joinFirewallError(fmt.Errorf("сохранение ruleset IPv6: %w", err), restoreErr)
	}
	if _, err := s.Runner.RunInput(ctx, rs.IPv6, s.restore6Cmd()); err != nil {
		// Ядро может быть собрано без IPv6 вовсе — тогда блокировать нечего.
		if !missingIPv6Tables(err) {
			return s.rollbackApply(ctx, fmt.Errorf("применение правил ip6tables: %w", err), previous4, previous6, previousLive)
		}
	}
	if _, err := s.Runner.RunInput(ctx, rs.IPv4, s.restoreCmd()); err != nil {
		return s.rollbackApply(ctx, fmt.Errorf("применение правил iptables: %w", err), previous4, previous6, previousLive)
	}

	return nil
}

// Health проверяет, что цепочки netOS действительно на месте. Если что-то
// сбросило правила между применением и проверкой, лучше узнать об этом сразу
// и откатиться, чем оставить роутер с политикой DROP и без разрешающих правил.
func (s *Subsystem) Health(ctx context.Context, cfg *config.Config) error {
	expected, err := Build(cfg)
	if err != nil {
		return err
	}
	ipv4OK, ipv6OK, err := s.liveMatches(ctx, expected)
	if err != nil {
		return err
	}
	if !ipv4OK {
		return fmt.Errorf("живые правила iptables не соответствуют конфигурации")
	}
	if !ipv6OK {
		return fmt.Errorf("живые правила ip6tables не соответствуют конфигурации")
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

type rulesetSnapshot struct {
	path   string
	data   []byte
	exists bool
}

type liveRulesetSnapshot struct {
	ipv4        string
	ipv6        string
	ipv6Missing bool
}

func snapshotRuleset(path string) (rulesetSnapshot, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return rulesetSnapshot{path: path}, nil
	}
	if err != nil {
		return rulesetSnapshot{}, err
	}
	return rulesetSnapshot{path: path, data: data, exists: true}, nil
}

func restoreRulesetSnapshot(snapshot rulesetSnapshot) error {
	if snapshot.exists {
		return system.WriteFileAtomic(snapshot.path, snapshot.data, 0o600)
	}
	if err := os.Remove(snapshot.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func rulesetFileReady(path string, expected []byte) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		return false
	}
	data, err := os.ReadFile(path)
	return err == nil && string(data) == string(expected)
}

func persistRulesetPair(path4 string, data4 []byte, path6 string, data6 []byte) error {
	previous4, err := snapshotRuleset(path4)
	if err != nil {
		return fmt.Errorf("чтение предыдущего ruleset: %w", err)
	}
	previous6, err := snapshotRuleset(path6)
	if err != nil {
		return fmt.Errorf("чтение предыдущего ruleset IPv6: %w", err)
	}
	if err := system.WriteFileAtomic(path4, data4, 0o600); err != nil {
		return fmt.Errorf("сохранение ruleset: %w", err)
	}
	if err := system.WriteFileAtomic(path6, data6, 0o600); err != nil {
		rollbackErr := restoreRulesetSnapshot(previous4)
		if restore6Err := restoreRulesetSnapshot(previous6); restore6Err != nil {
			if rollbackErr == nil {
				rollbackErr = restore6Err
			} else {
				rollbackErr = fmt.Errorf("%v; IPv6: %w", rollbackErr, restore6Err)
			}
		}
		return joinFirewallError(fmt.Errorf("сохранение ruleset IPv6: %w", err), rollbackErr)
	}
	return nil
}

func (s *Subsystem) rollbackApply(ctx context.Context, cause error, previous4, previous6 rulesetSnapshot, live liveRulesetSnapshot) error {
	var rollbackErrs []string
	for _, snapshot := range []rulesetSnapshot{previous4, previous6} {
		if err := restoreRulesetSnapshot(snapshot); err != nil {
			rollbackErrs = append(rollbackErrs, err.Error())
		}
	}
	if !live.ipv6Missing {
		if _, err := s.Runner.RunInput(ctx, live.ipv6, s.restore6Cmd()); err != nil && !missingIPv6Tables(err) {
			rollbackErrs = append(rollbackErrs, "ip6tables: "+err.Error())
		}
	}
	if _, err := s.Runner.RunInput(ctx, live.ipv4, s.restoreCmd()); err != nil {
		rollbackErrs = append(rollbackErrs, "iptables: "+err.Error())
	}
	if len(rollbackErrs) != 0 {
		return fmt.Errorf("%w; восстановление предыдущих правил: %s", cause, strings.Join(rollbackErrs, "; "))
	}
	return cause
}

func joinFirewallError(cause, rollback error) error {
	if rollback == nil {
		return cause
	}
	return fmt.Errorf("%w; восстановление предыдущего ruleset: %v", cause, rollback)
}

func missingIPv6Tables(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "does not exist") || strings.Contains(text, "no such file") || strings.Contains(text, "not found")
}

func (s *Subsystem) liveMatches(ctx context.Context, expected *Ruleset) (ipv4OK, ipv6OK bool, err error) {
	live, err := s.snapshotLive(ctx)
	if err != nil {
		return false, false, err
	}
	return rulesetMatches(live.ipv4, expected.IPv4), live.ipv6Missing || rulesetMatches(live.ipv6, expected.IPv6), nil
}

func (s *Subsystem) snapshotLive(ctx context.Context) (liveRulesetSnapshot, error) {
	save4, save6 := "iptables-save", "ip6tables-save"
	if s.Legacy {
		save4, save6 = "iptables-legacy-save", "ip6tables-legacy-save"
	}
	live4, err := s.Runner.Run(ctx, save4)
	if err != nil {
		return liveRulesetSnapshot{}, fmt.Errorf("чтение текущих правил iptables: %w", err)
	}
	live6, err := s.Runner.Run(ctx, save6)
	if err != nil {
		if missingIPv6Tables(err) {
			return liveRulesetSnapshot{ipv4: live4, ipv6Missing: true}, nil
		}
		return liveRulesetSnapshot{}, fmt.Errorf("чтение текущих правил ip6tables: %w", err)
	}
	return liveRulesetSnapshot{ipv4: live4, ipv6: live6}, nil
}

func normalizeRuleset(ruleset string) string {
	var normalized []string
	for _, raw := range strings.Split(strings.ReplaceAll(ruleset, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, ":") {
			if counter := strings.LastIndex(line, " ["); counter >= 0 && strings.HasSuffix(line, "]") {
				line = line[:counter] + " [0:0]"
			}
		}
		normalized = append(normalized, line)
	}
	return strings.Join(normalized, "\n")
}

func rulesetMatches(live, expected string) bool {
	liveTables := rulesetTables(normalizeRuleset(live))
	expectedTables := rulesetTables(normalizeRuleset(expected))
	for name, expectedTable := range expectedTables {
		if liveTables[name] != expectedTable {
			return false
		}
	}
	return true
}

func rulesetTables(normalized string) map[string]string {
	tables := map[string]string{}
	var name string
	var lines []string
	for _, line := range strings.Split(normalized, "\n") {
		if strings.HasPrefix(line, "*") {
			name = strings.TrimPrefix(line, "*")
			lines = []string{line}
			continue
		}
		if name == "" {
			continue
		}
		lines = append(lines, line)
		if line == "COMMIT" {
			tables[name] = canonicalTable(lines)
			name = ""
			lines = nil
		}
	}
	return tables
}

// canonicalTable mirrors the harmless formatting performed by the nft-backed
// iptables-save implementation.  It emits chain declarations alphabetically
// and groups rules by chain, while preserving the order of rules inside each
// chain (the part that changes packet semantics).
func canonicalTable(lines []string) string {
	chains := map[string]string{}
	rules := map[string][]string{}
	var other []string
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "*") || line == "COMMIT":
			continue
		case strings.HasPrefix(line, ":"):
			name := strings.Fields(strings.TrimPrefix(line, ":"))
			if len(name) > 0 {
				chains[name[0]] = line
			}
		case strings.HasPrefix(line, "-A "):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				rules[fields[1]] = append(rules[fields[1]], canonicalRule(line))
			}
		default:
			other = append(other, line)
		}
	}
	names := make([]string, 0, len(chains))
	for name := range chains {
		names = append(names, name)
	}
	sort.Strings(names)
	var result []string
	for _, name := range names {
		result = append(result, chains[name])
	}
	for _, name := range names {
		result = append(result, rules[name]...)
	}
	sort.Strings(other)
	result = append(result, other...)
	return strings.Join(result, "\n")
}

func canonicalRule(line string) string {
	for _, protocol := range []string{"tcp", "udp", "icmp", "icmpv6"} {
		if strings.Contains(line, "-p "+protocol) {
			line = strings.ReplaceAll(line, " -m "+protocol+" ", " ")
		}
	}
	for _, option := range []string{"--ctstate ", "--state "} {
		start := strings.Index(line, option)
		if start < 0 {
			continue
		}
		valueStart := start + len(option)
		valueEnd := strings.IndexByte(line[valueStart:], ' ')
		if valueEnd < 0 {
			valueEnd = len(line)
		} else {
			valueEnd += valueStart
		}
		states := strings.Split(line[valueStart:valueEnd], ",")
		sort.Strings(states)
		line = line[:valueStart] + strings.Join(states, ",") + line[valueEnd:]
	}
	return line
}
