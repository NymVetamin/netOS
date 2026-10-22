//go:build linux

package system

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

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
	e := NewExec()
	check := func(want, black bool) {
		t.Helper()
		a, b, err := e.ChannelRouteState(context.Background(), 1234, "qa-route0")
		if err != nil || a != want || b != black {
			t.Fatalf("got %v %v %v want %v %v", a, b, err, want, black)
		}
	}
	check(false, false)
	ip("route", "add", "default", "dev", "qa-route0", "table", "1234", "metric", "100")
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
}
