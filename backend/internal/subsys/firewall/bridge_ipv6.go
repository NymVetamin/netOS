package firewall

import (
	"context"
	"fmt"
	"strings"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

const bridgeIPv6Chain = "NETOS-IPV6"

var bridgeIPv6Hooks = []string{"INPUT", "FORWARD", "OUTPUT"}

// BridgeIPv6 suppresses Ethernet forwarding as well as the IPv6 host stack.
// Disabling IPv6 sysctls does not stop a Linux bridge forwarding IPv6 frames.
// ebtables comes with the required iptables package and does not require
// br_netfilter, whose IPv4 hooks would also change ordinary LAN forwarding.
type BridgeIPv6 struct{ Runner system.Runner }

func NewBridgeIPv6(r system.Runner) *BridgeIPv6 { return &BridgeIPv6{Runner: r} }
func (s *BridgeIPv6) Name() string              { return "bridge-ipv6" }

type bridgeIPv6State struct {
	chain bool
	drop  bool
	rules []string
}

func readBridgeIPv6(ctx context.Context, run func(context.Context, string, ...string) (string, error)) (bridgeIPv6State, error) {
	out, err := run(ctx, "ebtables-save")
	if err != nil {
		return bridgeIPv6State{}, fmt.Errorf("чтение Ethernet-фильтра IPv6: %w", err)
	}
	var state bridgeIPv6State
	filter := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "*") {
			filter = line == "*filter"
			continue
		}
		if !filter {
			continue
		}
		if strings.HasPrefix(line, ":"+bridgeIPv6Chain+" ") {
			state.chain = true
			state.drop = strings.Fields(line)[1] == "DROP"
		}
		if strings.HasPrefix(line, "-A ") {
			state.rules = append(state.rules, strings.Join(strings.Fields(line), " "))
		}
	}
	return state, nil
}

func bridgeIPv6Hook(chain string) string {
	return "-A " + chain + " -p IPv6 -j " + bridgeIPv6Chain
}

func (state bridgeIPv6State) ready(off bool) bool {
	if !off {
		return !state.chain
	}
	if !state.chain || !state.drop {
		return false
	}
	for _, rule := range state.rules {
		if strings.HasPrefix(rule, "-A "+bridgeIPv6Chain+" ") {
			return false
		}
	}
	for _, hook := range bridgeIPv6Hooks {
		first, count := "", 0
		for _, rule := range state.rules {
			if strings.HasPrefix(rule, "-A "+hook+" ") && first == "" {
				first = rule
			}
			if rule == bridgeIPv6Hook(hook) {
				count++
			}
		}
		if first != bridgeIPv6Hook(hook) || count != 1 {
			return false
		}
	}
	return true
}

func (s *BridgeIPv6) Plan(old, new *config.Config) ([]apply.Action, error) {
	state, err := readBridgeIPv6(context.Background(), s.Runner.Run)
	if err != nil {
		return nil, err
	}
	if state.ready(new.IPv6.Mode == "off") {
		return nil, nil
	}
	return []apply.Action{{Kind: "update", Target: "IPv6 на Ethernet-мостах", Detail: "режим " + new.IPv6.Mode, Disruptive: true}}, nil
}

func (s *BridgeIPv6) Apply(ctx context.Context, cfg *config.Config) error {
	if cfg.IPv6.Mode != "off" {
		return ClearBridgeIPv6(ctx, s.Runner.Run)
	}
	state, err := readBridgeIPv6(ctx, s.Runner.Run)
	if err != nil || state.ready(true) {
		return err
	}
	run := func(args ...string) error {
		_, err := s.Runner.Run(ctx, "ebtables", args...)
		return err
	}
	if !state.chain {
		if err := run("-N", bridgeIPv6Chain); err != nil {
			return err
		}
	}
	if err := run("-P", bridgeIPv6Chain, "DROP"); err != nil {
		return err
	}
	if err := run("-F", bridgeIPv6Chain); err != nil {
		return err
	}
	for _, hook := range bridgeIPv6Hooks {
		// Insert first before removing older copies, so repair never opens a
		// forwarding window or lets a pre-existing ACCEPT bypass suppression.
		if err := run("-I", hook, "1", "-p", "IPv6", "-j", bridgeIPv6Chain); err != nil {
			return err
		}
		// Delete old copies by position, from the end. Rule-spec deletion
		// would remove the new first rule instead.
		position := 1
		var duplicates []int
		for _, rule := range state.rules {
			if strings.HasPrefix(rule, "-A "+hook+" ") {
				position++
				if rule == bridgeIPv6Hook(hook) {
					duplicates = append(duplicates, position)
				}
			}
		}
		for i := len(duplicates) - 1; i >= 0; i-- {
			if err := run("-D", hook, fmt.Sprint(duplicates[i])); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *BridgeIPv6) Health(ctx context.Context, cfg *config.Config) error {
	state, err := readBridgeIPv6(ctx, s.Runner.Run)
	if err != nil {
		return err
	}
	if !state.ready(cfg.IPv6.Mode == "off") {
		return fmt.Errorf("Ethernet-фильтр IPv6 не соответствует режиму %s", cfg.IPv6.Mode)
	}
	return nil
}

// ClearBridgeIPv6 is shared by passthrough and uninstall. Other bridge rules,
// chains and policies are left intact, including rules added after netOS.
func ClearBridgeIPv6(ctx context.Context, run func(context.Context, string, ...string) (string, error)) error {
	state, err := readBridgeIPv6(ctx, run)
	if err != nil || !state.chain {
		return err
	}
	for _, rule := range state.rules {
		for _, hook := range bridgeIPv6Hooks {
			if rule == bridgeIPv6Hook(hook) {
				args := strings.Fields(rule)
				args[0] = "-D"
				if _, err := run(ctx, "ebtables", args...); err != nil {
					return err
				}
			}
		}
	}
	if _, err := run(ctx, "ebtables", "-F", bridgeIPv6Chain); err != nil {
		return err
	}
	_, err = run(ctx, "ebtables", "-X", bridgeIPv6Chain)
	return err
}
