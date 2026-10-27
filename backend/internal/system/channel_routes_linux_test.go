//go:build linux

package system

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Each sample reads one channel with unrelated channel tables present, just as
// the monitor does. Run only in an isolated namespace; no host routes are used.
func BenchmarkChannelRouteStateKernel(b *testing.B) {
	if os.Getenv("NETOS_TEST_NETWORK_NAMESPACE") != "1" {
		b.Skip("requires isolated network namespace")
	}
	ip := func(args ...string) {
		b.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			b.Fatalf("ip %v: %s %v", args, out, err)
		}
	}
	ip("link", "add", "qa-bench0", "type", "dummy")
	defer exec.Command("ip", "link", "del", "qa-bench0").Run()
	ip("link", "set", "qa-bench0", "up")
	for _, count := range []int{1, 20, 200} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			for i := 0; i < count; i++ {
				table := fmt.Sprint(1001 + i)
				ip("route", "replace", "default", "dev", "qa-bench0", "table", table, "metric", "100")
				ip("route", "replace", "blackhole", "default", "table", table, "metric", "1000")
			}
			e := NewExec()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				normal, blackhole, err := e.ChannelRouteState(context.Background(), 1001, "qa-bench0")
				if err != nil || !normal || !blackhole {
					b.Fatalf("got %v %v %v", normal, blackhole, err)
				}
			}
			b.StopTimer()
			for i := 0; i < count; i++ {
				ip("route", "flush", "table", fmt.Sprint(1001+i))
			}
		})
	}
}

func TestChannelRouteMatch(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		table, oif, kind, prefix int
		normal, blackhole        bool
	}{
		{"default", 1234, 7, unix.RTN_UNICAST, 0, true, false},
		{"other table", 1235, 7, unix.RTN_UNICAST, 0, false, false},
		{"other interface", 1234, 8, unix.RTN_UNICAST, 0, false, false},
		{"subnet", 1234, 7, unix.RTN_UNICAST, 24, false, false},
		{"blackhole", 1234, 0, unix.RTN_BLACKHOLE, 0, false, true},
		{"unreachable", 1234, 0, unix.RTN_UNREACHABLE, 0, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, unix.SizeofRtMsg+16)
			data[0], data[1], data[7] = unix.AF_INET, byte(tc.prefix), byte(tc.kind)
			for i, a := range []struct {
				kind  uint16
				value int
			}{{unix.RTA_TABLE, tc.table}, {unix.RTA_OIF, tc.oif}} {
				b := data[unix.SizeofRtMsg+i*8:]
				binary.NativeEndian.PutUint16(b, 8)
				binary.NativeEndian.PutUint16(b[2:], a.kind)
				binary.NativeEndian.PutUint32(b[4:], uint32(a.value))
			}
			a, b, err := channelRouteMatch(syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWROUTE}, Data: data}, 1234, 7)
			if err != nil || a != tc.normal || b != tc.blackhole {
				t.Fatalf("got %v %v %v", a, b, err)
			}
		})
	}
	if _, _, err := channelRouteMatch(syscall.NetlinkMessage{Data: []byte{1}}, 1, 1); err == nil {
		t.Fatal("short message accepted")
	}
}

// Run only inside a fresh, isolated `unshare --net` namespace on the QA host.
func TestChannelRouteStateKernel(t *testing.T) {
	if os.Getenv("NETOS_TEST_NETWORK_NAMESPACE") != "1" {
		t.Skip("requires isolated network namespace")
	}
	// Removing the device does not remove the table's blackhole route.
	// Clean it too so repeated runs in the same namespace start empty.
	t.Cleanup(func() { exec.Command("ip", "route", "flush", "table", "1234").Run() })
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %s %v", args, out, err)
		}
	}
	ip("link", "add", "qa-route0", "type", "dummy")
	defer exec.Command("ip", "link", "del", "qa-route0").Run()
	ip("link", "set", "qa-route0", "up")
	ip("link", "add", "qa-route1", "type", "dummy")
	defer exec.Command("ip", "link", "del", "qa-route1").Run()
	ip("link", "set", "qa-route1", "up")
	// Neither foreign-table defaults nor a subnet in the requested table may
	// hide missing channel defaults. Cover table IDs beyond the rtmsg byte.
	for _, table := range []string{"254", "1235", "70000"} {
		ip("route", "add", "default", "dev", "qa-route0", "table", table)
	}
	e := NewExec()
	check := func(want, black bool) {
		t.Helper()
		a, b, err := e.ChannelRouteState(context.Background(), 1234, "qa-route0")
		if err != nil || a != want || b != black {
			t.Fatalf("got %v %v %v want %v %v", a, b, err, want, black)
		}
	}
	check(false, false)
	ip("route", "add", "192.0.2.0/24", "dev", "qa-route0", "table", "1234")
	ip("route", "add", "default", "dev", "qa-route1", "table", "1234", "metric", "200")
	check(false, false)
	ip("route", "add", "default", "dev", "qa-route0", "table", "1234", "metric", "100")
	ip("route", "add", "blackhole", "default", "table", "1234", "metric", "1000")
	check(true, true)
	ip("route", "del", "blackhole", "default", "table", "1234", "metric", "1000")
	check(true, false)
	ip("route", "add", "blackhole", "default", "table", "1234", "metric", "1000")
	check(true, true)
	ip("route", "del", "default", "dev", "qa-route0", "table", "1234", "metric", "100")
	check(false, true)
	ip("link", "del", "qa-route0")
	ip("link", "add", "qa-route0", "type", "dummy")
	ip("link", "set", "qa-route0", "up")
	check(false, true)
	ip("route", "add", "default", "dev", "qa-route0", "table", "1234", "metric", "100")
	check(true, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := e.ChannelRouteState(ctx, 1234, "qa-route0"); err == nil {
		t.Fatal("cancellation ignored")
	}
	if _, _, err := e.ChannelRouteState(context.Background(), 1234, "qa-missing"); err == nil {
		t.Fatal("missing interface accepted")
	}
}
