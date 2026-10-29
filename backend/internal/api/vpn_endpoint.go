package api

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/ddns"
)

type vpnEndpointSuggestion struct {
	Host   string `json:"host"`
	Source string `json:"source"`
}

// Discovery is requested by the editor, never by a background poller.
// It changes neither DDNS state nor the VPN listener configuration.
func suggestVPNEndpoint(ctx context.Context, cfg *config.Config, resolver *ddns.Controller) (vpnEndpointSuggestion, error) {
	if cfg.DDNS.Enabled && strings.TrimSpace(cfg.DDNS.Hostname) != "" {
		return vpnEndpointSuggestion{Host: strings.TrimSpace(cfg.DDNS.Hostname), Source: "ddns"}, nil
	}
	if resolver == nil || resolver.ResolveAddress == nil {
		return vpnEndpointSuggestion{}, fmt.Errorf("определение внешнего адреса недоступно")
	}
	var preferred *config.WAN
	for i := range cfg.WANs {
		wan := &cfg.WANs[i]
		if wan.Enabled && (preferred == nil || wan.Metric < preferred.Metric) {
			preferred = wan
		}
	}
	copy := *cfg
	if preferred != nil {
		copy.DDNS = config.DDNS{AddressSource: "interface", WAN: preferred.ID}
		if address, err := resolver.ResolveAddress(ctx, &copy); err == nil && publicVPNIPv4(address) {
			return vpnEndpointSuggestion{Host: address, Source: "wan"}, nil
		}
	}
	copy.DDNS = config.DDNS{AddressSource: "web"}
	address, err := resolver.ResolveAddress(ctx, &copy)
	if err != nil || !publicVPNIPv4(address) {
		return vpnEndpointSuggestion{}, fmt.Errorf("не удалось определить внешний IPv4-адрес; укажите адрес подключения вручную")
	}
	return vpnEndpointSuggestion{Host: address, Source: "external"}, nil
}

func publicVPNIPv4(value string) bool {
	ip, err := netip.ParseAddr(value)
	if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() {
		return false
	}
	for _, subnet := range []string{"0.0.0.0/8", "100.64.0.0/10", "198.18.0.0/15", "240.0.0.0/4"} {
		if netip.MustParsePrefix(subnet).Contains(ip) {
			return false
		}
	}
	return true
}

func (s *Server) handleVPNEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	value, err := suggestVPNEndpoint(ctx, s.Engine.Current(), s.DDNS)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}
