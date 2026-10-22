package runtime

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/monitor"
)

// RealtimeIdentities is called on topology changes or once per 30s, not for
// each speed sample. The history sampler and its persistence stay independent.
func (h *ClientHistory) RealtimeIdentities(ctx context.Context, cfg *config.Config) map[string]ClientCounter {
	return h.identity(ctx, cfg)
}
func (h *ClientHistory) RealtimeCounters(ctx context.Context) (map[string]ClientCounter, error) {
	if reader, ok := h.Runner.(interface {
		NFTSetCounters(context.Context, string) (map[string]map[string]uint64, error)
	}); ok {
		sets, err := reader.NFTSetCounters(ctx, monitor.Table)
		if err == nil {
			result := map[string]ClientCounter{}
			for name, counts := range sets {
				for address, bytes := range counts {
					v := result[address]
					v.Address = address
					if strings.HasPrefix(name, "up") {
						v.TX += bytes
					} else {
						v.RX += bytes
					}
					result[address] = v
				}
			}
			return result, nil
		}
		// Preserve the existing reader if native dumps are unavailable/interrupted.
	}
	raw, err := h.Runner.Run(ctx, "nft", "-j", "list", "table", "inet", monitor.Table)
	if err != nil {
		return nil, err
	}
	return ParseClientCounters(raw)
}

func RealtimeInterfaces() (map[string]ClientCounter, error) {
	raw, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	return ParseInterfaceCounters(string(raw)), nil
}
func ParseInterfaceCounters(raw string) map[string]ClientCounter {
	result := map[string]ClientCounter{}
	for _, line := range strings.Split(raw, "\n") {
		name, values, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		fields := strings.Fields(values)
		if len(fields) < 16 || name == "lo" {
			continue
		}
		rx, e1 := strconv.ParseUint(fields[0], 10, 64)
		tx, e2 := strconv.ParseUint(fields[8], 10, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		result[name] = ClientCounter{ID: "if:" + name, Name: name, RX: rx, TX: tx}
	}
	return result
}
