package system

import (
	"strings"
	"testing"
)

func TestReplayableRouteFieldsDropsEveryPrintedStateFlag(t *testing.T) {
	// Каждый из флагов iproute2 6.15 на входе отвергает как «garbage».
	line := "198.51.100.0/24 via 192.0.2.2 dev d0 proto static metric 5 onlink linkdown dead pervasive offload trap notify unresolved rt_offload rt_trap rt_offload_failed"
	got := strings.Join(ReplayableRouteFields(line), " ")
	if want := "198.51.100.0/24 via 192.0.2.2 dev d0 proto static metric 5 onlink"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if fields := ReplayableRouteFields("  \t "); len(fields) != 0 {
		t.Fatalf("empty line produced %q", fields)
	}
}
