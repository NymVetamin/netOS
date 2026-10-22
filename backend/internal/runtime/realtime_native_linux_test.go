//go:build linux

package runtime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/system"
)

// Hide the optional native reader to exercise the original command path.
type commandCountersOnly struct{ system.Runner }
type interruptedCounters struct{ *system.Exec }

func (r interruptedCounters) NFTSetCounters(context.Context, string) (map[string]map[string]uint64, error) {
	return nil, errors.New("interrupted dump")
}

func TestRealtimeCountersKernelEquivalence(t *testing.T) {
	if os.Getenv("NETOS_TEST_NETWORK_NAMESPACE") != "1" {
		t.Skip("requires isolated network namespace")
	}
	run := func(s string) {
		t.Helper()
		c := exec.Command("nft", "-f", "-")
		c.Stdin = strings.NewReader(s)
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("nft: %s %v", out, err)
		}
	}
	run(`add table inet netos_traffic_monitor
add set inet netos_traffic_monitor up4 { type ipv4_addr; flags dynamic,timeout; timeout 24h; counter; }
add set inet netos_traffic_monitor down4 { type ipv4_addr; flags dynamic,timeout; timeout 24h; counter; }
add set inet netos_traffic_monitor up6 { type ipv6_addr; flags dynamic,timeout; timeout 24h; counter; }
add set inet netos_traffic_monitor down6 { type ipv6_addr; flags dynamic,timeout; timeout 24h; counter; }
`)
	e := system.NewExec()
	e.Timeout = 2 * time.Second
	native := &ClientHistory{Runner: e}
	old := &ClientHistory{Runner: commandCountersOnly{e}}
	fallback := &ClientHistory{Runner: interruptedCounters{e}}
	check := func() {
		t.Helper()
		want, err := old.RealtimeCounters(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range []*ClientHistory{native, fallback} {
			got, err := h.RealtimeCounters(context.Background())
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("native/fallback=%v err=%v old=%v", got, err, want)
			}
		}
	}
	check()
	run(`add element inet netos_traffic_monitor up4 { 192.0.2.1 counter packets 1 bytes 9007199254740993, 192.0.2.2 counter packets 0 bytes 0 }
add element inet netos_traffic_monitor down4 { 192.0.2.1 counter packets 1 bytes 987654321 }
add element inet netos_traffic_monitor up6 { 2001:db8::1 counter packets 1 bytes 123456789, ::ffff:192.0.2.5 counter packets 1 bytes 55 }
add element inet netos_traffic_monitor down6 { 2001:db8::1 counter packets 1 bytes 9999999999 }
`)
	check()
	want, err := old.RealtimeCounters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fdsBefore, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				got, err := native.RealtimeCounters(context.Background())
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Errorf("concurrent read mismatch: %v %v", got, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	fdsAfter, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(fdsAfter) > len(fdsBefore)+1 {
		t.Fatalf("descriptor leak: before=%d after=%d err=%v", len(fdsBefore), len(fdsAfter), err)
	}
	check() // All reads must leave counters unchanged.
	run("delete element inet netos_traffic_monitor up4 { 192.0.2.1 }")
	check()
	run("delete table inet netos_traffic_monitor")
	for _, h := range []*ClientHistory{native, old, fallback} {
		if _, err := h.RealtimeCounters(context.Background()); err == nil {
			t.Fatal("missing table silently accepted")
		}
	}
}
