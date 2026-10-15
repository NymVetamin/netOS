package socks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/channels"
	"github.com/netos-router/netos/internal/system"
)

const Unit = "netos-socks.service"

type Subsystem struct {
	Runner            system.Runner
	StateDir, UnitDir string
}

func New(r system.Runner, stateDir string) *Subsystem {
	return &Subsystem{r, stateDir, "/etc/systemd/system"}
}
func (s *Subsystem) Name() string { return "socks" }
func (s *Subsystem) paths() (string, string) {
	return filepath.Join(s.StateDir, "socks.json"), filepath.Join(s.UnitDir, Unit)
}
func Render(c *config.Config) ([]byte, error) {
	p := c.Socks
	mark := 0
	found := false
	for _, ch := range c.Channels {
		if ch.Enabled && ch.ID == p.Channel {
			found = true
			if ch.Type != "direct" {
				mark = channels.Mark(ch)
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("выбранный выход SOCKS5 выключен или отсутствует")
	}
	settings := map[string]any{"auth": "noauth", "udp": false}
	if p.Auth {
		settings["auth"] = "password"
		settings["accounts"] = []any{map[string]any{"user": p.Username, "pass": p.Password}}
	}
	// IPv4 only: prevent IPv6 destinations escaping IPv4 channel policy routing.
	return json.MarshalIndent(map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{"tag": "socks", "listen": "0.0.0.0", "port": p.Port, "protocol": "socks", "settings": settings}},
		"outbounds": []any{
			map[string]any{"tag": "exit", "protocol": "freedom", "settings": map[string]any{"domainStrategy": "ForceIPv4", "finalRules": []any{map[string]any{"action": "allow"}}}, "streamSettings": map[string]any{"sockopt": map[string]any{"mark": mark}}},
			map[string]any{"tag": "block", "protocol": "blackhole"}},
		"routing": map[string]any{"rules": []any{map[string]any{"type": "field", "ip": []string{"::/0"}, "outboundTag": "block"}}},
	}, "", "  ")
}
func (s *Subsystem) stamp(c *config.Config) []byte {
	rendered, _ := Render(c)
	data, _ := json.Marshal(struct {
		Settings config.Socks
		Rendered string
	}{c.Socks, string(rendered)})
	return data
}
func (s *Subsystem) changed(c *config.Config) bool {
	return system.FileChanged(filepath.Join(s.StateDir, "socks.applied"), s.stamp(c))
}
func (s *Subsystem) Plan(old, next *config.Config) ([]apply.Action, error) {
	if !next.Socks.Enabled && (old == nil || !old.Socks.Enabled) {
		return nil, nil
	}
	if old == nil || !reflect.DeepEqual(s.stamp(old), s.stamp(next)) || s.changed(next) {
		return []apply.Action{{Subsystem: s.Name(), Kind: "update", Target: "SOCKS5-прокси", Detail: "доступ, авторизация и канал выхода", Disruptive: true}}, nil
	}
	return nil, nil
}

// Prepare stops a changing listener before firewall permissions move to a new
// port/scope. Startup is deliberately controlled by netosd AFTER firewall Apply,
// rather than enabling an unauthenticated socket early during OS boot.
type Preparation struct{ S *Subsystem }

func (p *Preparation) Name() string                                     { return "socks-prepare" }
func (p *Preparation) Plan(a, b *config.Config) ([]apply.Action, error) { return nil, nil }
func (p *Preparation) Health(context.Context, *config.Config) error     { return nil }
func (p *Preparation) Apply(ctx context.Context, c *config.Config) error {
	_, unit := p.S.paths()
	if _, err := os.Stat(unit); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if p.S.changed(c) || !c.Socks.Enabled {
		_, err := p.S.Runner.Run(ctx, "systemctl", "stop", Unit)
		return err
	}
	return nil
}
func (s *Subsystem) Apply(ctx context.Context, c *config.Config) error {
	conf, unit := s.paths()
	if !c.Socks.Enabled {
		_, statErr := os.Stat(unit)
		if statErr != nil && !os.IsNotExist(statErr) {
			return statErr
		}
		if statErr == nil {
			if _, err := s.Runner.Run(ctx, "systemctl", "stop", Unit); err != nil {
				return err
			}
		}
		for _, p := range []string{unit, conf, filepath.Join(s.StateDir, "socks.applied")} {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		if statErr == nil {
			_, err := s.Runner.Run(ctx, "systemctl", "daemon-reload")
			return err
		}
		return nil
	}

	data, err := Render(c)
	if err != nil {
		return err
	}
	candidate := strings.TrimSuffix(conf, ".json") + ".candidate.json"
	if _, err = system.WriteFileAtomicIfChanged(candidate, data, 0600); err != nil {
		return err
	}
	defer os.Remove(candidate)
	if _, err = s.Runner.Run(ctx, "/usr/local/bin/xray", "run", "-test", "-config", candidate); err != nil {
		return fmt.Errorf("проверка SOCKS5: %w", err)
	}
	unitData := []byte("[Unit]\nDescription=netOS SOCKS5 proxy\nAfter=network.target\n[Service]\nType=simple\nUMask=0077\nExecStart=/usr/local/bin/xray run -config " + conf + "\nRestart=on-failure\nRestartSec=3\nNoNewPrivileges=true\nProtectHome=true\nProtectSystem=strict\nPrivateTmp=true\nCapabilityBoundingSet=CAP_NET_ADMIN\n")
	changed := s.changed(c) || system.FileChanged(conf, data) || system.FileChanged(unit, unitData)
	if _, err = system.WriteFileAtomicIfChanged(conf, data, 0600); err != nil {
		return err
	}
	if _, err = system.WriteFileAtomicIfChanged(unit, unitData, 0644); err != nil {
		return err
	}
	if changed {
		if _, err = s.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	active, _ := s.Runner.Run(ctx, "systemctl", "is-active", Unit)
	if changed || strings.TrimSpace(active) != "active" {
		if _, err = s.Runner.Run(ctx, "systemctl", "restart", Unit); err != nil {
			return err
		}
	}
	if err = s.Health(ctx, c); err != nil {
		return err
	}
	_, err = system.WriteFileAtomicIfChanged(filepath.Join(s.StateDir, "socks.applied"), s.stamp(c), 0600)
	return err
}
func (s *Subsystem) Health(ctx context.Context, c *config.Config) error {
	if !c.Socks.Enabled {
		return nil
	}
	out, err := s.Runner.Run(ctx, "systemctl", "is-active", Unit)
	if err != nil || strings.TrimSpace(out) != "active" {
		return fmt.Errorf("SOCKS5 не запущен")
	}
	return nil
}
