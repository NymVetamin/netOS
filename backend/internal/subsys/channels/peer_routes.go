package channels

import (
	"context"
	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
)

// The first channels phase installs fail-closed rules. Server interfaces only
// exist after vpn-servers; finish their routes before policies are installed.
type PeerRoutes struct{ S *Subsystem }

func (*PeerRoutes) Name() string                                     { return "peer-channels" }
func (*PeerRoutes) Plan(_, _ *config.Config) ([]apply.Action, error) { return nil, nil }
func (*PeerRoutes) Health(context.Context, *config.Config) error     { return nil } // checked by channels and vpn-servers
func (p *PeerRoutes) Apply(ctx context.Context, cfg *config.Config) error {
	p.S.mu.Lock()
	defer p.S.mu.Unlock()
	for _, ch := range cfg.Channels {
		if ch.Enabled && ch.WireGuardPeer != nil {
			if err := p.S.ensureRoutes(ctx, ch, InterfaceName(ch)); err != nil {
				return err
			}
		}
	}
	return nil
}
