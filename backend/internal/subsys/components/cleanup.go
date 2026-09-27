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
	protected := protectedComponentPackages(desiredComponentState(cfg))
	for _, id := range []string{"ipset", "samba"} {
		if cfg.HasComponent(id) {
			continue
		}
		info, _ := config.ComponentByID(id)
		if s.Components.componentRemovable(ctx, info, protected) {
			if err := s.Components.removeProtected(ctx, info, protected); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Cleanup) Health(ctx context.Context, cfg *config.Config) error {
	for _, id := range []string{"ipset", "samba"} {
		if cfg.HasComponent(id) {
			continue
		}
		info, _ := config.ComponentByID(id)
		if s.Components.componentRemovable(ctx, info, protectedComponentPackages(desiredComponentState(cfg))) {
			return fmt.Errorf("пакет %s остался после удаления компонента", id)
		}
	}
	return nil
}
