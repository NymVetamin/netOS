package components

import (
	"context"
	"fmt"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
)

type Cleanup struct{ Components *Subsystem }

func (s *Cleanup) Name() string                                     { return "components-cleanup" }
func (s *Cleanup) Plan(_, _ *config.Config) ([]apply.Action, error) { return nil, nil }
func (s *Cleanup) Apply(ctx context.Context, cfg *config.Config) error {
	if cfg.HasComponent("ipset") {
		return nil
	}
	info, _ := config.ComponentByID("ipset")
	protected := protectedComponentPackages(desiredComponentState(cfg))
	if !s.Components.componentRemovable(ctx, info, protected) {
		return nil
	}
	return s.Components.removeProtected(ctx, info, protected)
}
func (s *Cleanup) Health(ctx context.Context, cfg *config.Config) error {
	if cfg.HasComponent("ipset") {
		return nil
	}
	info, _ := config.ComponentByID("ipset")
	if s.Components.componentRemovable(ctx, info, protectedComponentPackages(desiredComponentState(cfg))) {
		return fmt.Errorf("пакет ipset остался после удаления компонента")
	}
	return nil
}
