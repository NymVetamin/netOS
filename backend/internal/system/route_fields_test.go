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

// Имя интерфейса задаёт администратор, и мост может называться trap или dead:
// значение после dev (а также имена таблиц и протоколов) — не флаг.
func TestReplayableRouteFieldsKeepsNamesEqualToFlags(t *testing.T) {
	line := "192.0.2.0/24 dev trap table dead proto notify scope link linkdown"
	got := strings.Join(ReplayableRouteFields(line), " ")
	if want := "192.0.2.0/24 dev trap table dead proto notify scope link"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
