// Package hostsettings применяет системные параметры самого роутера.
package hostsettings

import (
	"context"
	"fmt"
	"strings"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type Subsystem struct{ Runner system.Runner }

func New(r system.Runner) *Subsystem { return &Subsystem{Runner: r} }

func (s *Subsystem) Name() string { return "system" }

func (s *Subsystem) Plan(old, new *config.Config) ([]apply.Action, error) {
	if old == nil {
		return nil, nil
	}
	var actions []apply.Action
	if old.System.Hostname != new.System.Hostname {
		actions = append(actions, apply.Action{Kind: "update", Target: "имя хоста", Detail: new.System.Hostname})
	}
	if old.System.Timezone != new.System.Timezone {
		actions = append(actions, apply.Action{Kind: "update", Target: "часовой пояс", Detail: new.System.Timezone})
	}
	return actions, nil
}

func (s *Subsystem) Apply(ctx context.Context, cfg *config.Config) error {
	if _, err := s.Runner.Run(ctx, "hostnamectl", "set-hostname", cfg.System.Hostname); err != nil {
		return fmt.Errorf("смена имени хоста: %w", err)
	}
	if _, err := s.Runner.Run(ctx, "timedatectl", "set-timezone", cfg.System.Timezone); err != nil {
		return fmt.Errorf("смена часового пояса: %w", err)
	}
	return nil
}

func (s *Subsystem) Health(ctx context.Context, cfg *config.Config) error {
	host, err := s.Runner.Run(ctx, "hostnamectl", "--static")
	if err != nil {
		return err
	}
	if strings.TrimSpace(host) != cfg.System.Hostname {
		return fmt.Errorf("имя хоста не применено")
	}
	tz, err := s.Runner.Run(ctx, "timedatectl", "show", "--property=Timezone", "--value")
	if err != nil {
		return err
	}
	if strings.TrimSpace(tz) != cfg.System.Timezone {
		return fmt.Errorf("часовой пояс не применён")
	}
	return nil
}
