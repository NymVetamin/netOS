package ethernet

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/netos-router/netos/internal/system"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Run func(context.Context, string, ...string) (string, error)
type Settings struct {
	Supported  []string `json:"supported"`
	Advertised []string `json:"advertised"`
	Autoneg    bool     `json:"autoneg"`
	CanAutoneg bool     `json:"can_autoneg"`
	Speed      int      `json:"speed"`
	Duplex     string   `json:"duplex"`
}

var modePattern = regexp.MustCompile(`^[0-9]+base[A-Za-z0-9_-]+/(Full|Half)$`)

func ValidMode(mode string) bool {
	return mode == "" || mode == "auto" || modePattern.MatchString(mode)
}
func Parse(raw string) Settings {
	s := Settings{Supported: []string{}, Advertised: []string{}}
	section := ""
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Supported link modes:") {
			section = "supported"
			line = strings.TrimSpace(strings.TrimPrefix(line, "Supported link modes:"))
		} else if strings.HasPrefix(line, "Advertised link modes:") {
			section = "advertised"
			line = strings.TrimSpace(strings.TrimPrefix(line, "Advertised link modes:"))
		} else if strings.Contains(line, ":") {
			section = ""
		}
		for _, token := range strings.Fields(line) {
			if modePattern.MatchString(token) {
				if section == "supported" {
					s.Supported = append(s.Supported, token)
				}
				if section == "advertised" {
					s.Advertised = append(s.Advertised, token)
				}
			}
		}
		if strings.HasPrefix(line, "Supports auto-negotiation:") {
			s.CanAutoneg = strings.HasSuffix(line, "Yes")
		}
		if strings.HasPrefix(line, "Auto-negotiation:") {
			s.Autoneg = strings.HasSuffix(line, "on")
		}
		if strings.HasPrefix(line, "Speed:") {
			s.Speed, _ = strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, "Speed:")), "Mb/s"))
		}
		if strings.HasPrefix(line, "Duplex:") {
			s.Duplex = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "Duplex:")))
		}
	}
	return s
}
func Read(ctx context.Context, run Run, name string) (Settings, error) {
	raw, err := run(ctx, "ethtool", name)
	if err != nil {
		return Settings{}, fmt.Errorf("не удалось прочитать режимы %s (нужен ethtool): %w", name, err)
	}
	return Parse(raw), nil
}
func same(a, b Settings) bool {
	if a.Autoneg != b.Autoneg {
		return false
	}
	if !a.Autoneg {
		return a.Speed == b.Speed && a.Duplex == b.Duplex
	}
	x := append([]string{}, a.Advertised...)
	y := append([]string{}, b.Advertised...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, ",") == strings.Join(y, ",")
}
func desired(current Settings, mode string) (Settings, error) {
	if !current.CanAutoneg || len(current.Supported) == 0 {
		return Settings{}, fmt.Errorf("драйвер не предоставляет настраиваемые режимы автосогласования")
	}
	d := current
	d.Autoneg = true
	d.Advertised = nil
	for _, m := range current.Supported {
		if mode == "auto" || mode == m {
			d.Advertised = append(d.Advertised, m)
		}
	}
	if len(d.Advertised) == 0 {
		return Settings{}, fmt.Errorf("порт не поддерживает режим %s", mode)
	}
	return d, nil
}
func set(ctx context.Context, run Run, name string, current, want Settings) error {
	if same(current, want) {
		return nil
	}
	args := []string{"-s", name, "autoneg"}
	if want.Autoneg {
		args = append(args, "on", "advertise")
		for _, m := range current.Supported {
			value := "off"
			for _, v := range want.Advertised {
				if m == v {
					value = "on"
				}
			}
			args = append(args, m, value)
		}
	} else {
		args = append(args, "off", "speed", strconv.Itoa(want.Speed), "duplex", want.Duplex)
	}
	if _, err := run(ctx, "ethtool", args...); err != nil {
		return fmt.Errorf("режим порта %s: %w", name, err)
	}
	got, err := Read(ctx, run, name)
	if err != nil {
		return err
	}
	if !same(got, want) {
		return fmt.Errorf("драйвер %s не применил запрошенный режим", name)
	}
	return nil
}

// Apply preserves the exact original negotiation settings before any mutation.
// Passing no modes restores all owned ports (rollback or uninstall).
func Apply(ctx context.Context, run Run, path string, modes map[string]string) error {
	baseline := map[string]Settings{}
	raw, err := os.ReadFile(path)
	if err == nil {
		if err = json.Unmarshal(raw, &baseline); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if baseline == nil {
		baseline = map[string]Settings{}
	}
	save := func() error {
		raw, err := json.Marshal(baseline)
		if err != nil {
			return err
		}
		_, err = system.WriteFileAtomicIfChanged(path, raw, 0600)
		return err
	}
	for name, mode := range modes {
		if mode == "" {
			continue
		}
		cur, err := Read(ctx, run, name)
		if err != nil {
			return err
		}
		want, err := desired(cur, mode)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if _, ok := baseline[name]; !ok {
			if (cur.Autoneg && len(cur.Advertised) == 0) || (!cur.Autoneg && (cur.Speed <= 0 || (cur.Duplex != "full" && cur.Duplex != "half"))) {
				return fmt.Errorf("%s: исходный режим не удалось определить, изменение отменено", name)
			}
			baseline[name] = cur
			if err = save(); err != nil {
				return err
			}
		}
		if err = set(ctx, run, name, cur, want); err != nil {
			return err
		}
	}
	for name, original := range baseline {
		if modes[name] != "" {
			continue
		}
		cur, err := Read(ctx, run, name)
		if err != nil {
			return err
		}
		if err = set(ctx, run, name, cur, original); err != nil {
			return err
		}
		delete(baseline, name)
		if err = save(); err != nil {
			return err
		}
	}
	return nil
}
