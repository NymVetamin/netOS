package api

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// Outgoing connections take source ports only from ip_local_port_range, so a
// port below it cannot be stolen between freeTCPPort and the test's bind.
func TestFreeTCPPortIsOutsideEphemeralRange(t *testing.T) {
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		t.Skip(err)
	}
	low, _ := strconv.Atoi(strings.Fields(string(raw))[0])
	if low <= 1025 {
		t.Skip("no room below the ephemeral range")
	}
	for i := 0; i < 20; i++ {
		if port := freeTCPPort(t); port < 1024 || port >= low {
			t.Fatalf("port %d is not below the ephemeral range starting at %d", port, low)
		}
	}
}
