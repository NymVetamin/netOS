package firewall

import (
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestPortForwardOnlyMatchesRouterAddresses(t *testing.T) {
	for _, iface := range []string{"", "eth1"} {
		t.Run("interface="+iface, func(t *testing.T) {
			var b builder
			b.natDestination(config.NATRule{Name: "port-forward", Interface: iface, Protocol: "tcpudp", ExtPort: "8000", DestIP: "192.0.3.10", DestPort: "9000", AllowFrom: "198.18.0.0/24"})
			lines := strings.Split(strings.TrimSpace(b.String()), "\n")
			if len(lines) != 2 {
				t.Fatalf("expected TCP and UDP rules, got %v", lines)
			}
			for _, line := range lines {
				if !strings.Contains(line, " -m addrtype --dst-type LOCAL ") {
					t.Errorf("port forward can hijack routed traffic: %s", line)
				}
				if !strings.Contains(line, " -s 198.18.0.0/24 ") || !strings.Contains(line, "--to-destination 192.0.3.10:9000") {
					t.Errorf("lost port forward restrictions or target: %s", line)
				}
			}
		})
	}
}

func TestPortForwardEqualRangesPreservePortOffset(t *testing.T) {
	var b builder
	b.natDestination(config.NATRule{Protocol: "tcpudp", ExtPort: "18081-18082", DestIP: "192.0.2.10", DestPort: "8009-8010"})
	for _, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if !strings.Contains(line, "--to-destination 192.0.2.10:8009-8010/18081") {
			t.Errorf("range is a pool rather than shifted map: %s", line)
		}
	}
}
