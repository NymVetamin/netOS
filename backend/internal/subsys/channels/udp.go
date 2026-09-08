package channels

import (
	"context"
	"fmt"
	"strings"

	"github.com/netos-router/netos/internal/config"
)

// NAT is decided on the first packet of a connection. A UDP flow created on
// direct WAN otherwise keeps its no-NAT decision after returning to a VPN and
// is sent into the tunnel with the LAN source address. Refresh only this
// channel's outbound UDP flows when its routing rule actually changes.
func (s *Subsystem) refreshChannelUDP(ctx context.Context, ch config.Channel, changed bool) error {
	if changed {
		if s.pendingUDP == nil {
			s.pendingUDP = map[string]bool{}
		}
		s.pendingUDP[ch.ID] = true
	}
	if !s.pendingUDP[ch.ID] {
		return nil
	}
	filter := []string{"-f", "ipv4", "-p", "udp", "--mark", fmt.Sprintf("0x%x", Mark(ch))}
	_, err := s.Runner.Run(ctx, "conntrack", append([]string{"-D"}, filter...)...)
	if err != nil {
		// conntrack also exits nonzero when there are no matching flows.
		// Verify absence rather than depending on localized error text.
		out, checkErr := s.Runner.Run(ctx, "conntrack", append([]string{"-L"}, filter...)...)
		if checkErr != nil || strings.TrimSpace(out) != "" {
			return fmt.Errorf("обновление UDP-соединений канала %s: %w", ch.Name, err)
		}
	}
	delete(s.pendingUDP, ch.ID)
	return nil
}
