//go:build linux

package system

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ChannelRouteState reads the same IPv4 defaults as `ip -4 route show table`.
// It deliberately takes a fresh snapshot: TUN recreation and externally removed
// routes must still be detected on the next monitor tick.
func (e *Exec) ChannelRouteState(ctx context.Context, table int, name string) (bool, bool, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return false, false, err
	}
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req := make([]byte, unix.NLMSG_HDRLEN+unix.SizeofRtMsg)
	binary.NativeEndian.PutUint32(req, uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:], unix.RTM_GETROUTE)
	binary.NativeEndian.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(req[8:], 1)
	req[unix.NLMSG_HDRLEN] = unix.AF_INET
	messages, err := kernelDump(ctx, unix.NETLINK_ROUTE, req)
	if err != nil {
		return false, false, err
	}
	var normal, blackhole bool
	for _, m := range messages {
		if m.Header.Type != unix.RTM_NEWROUTE {
			continue
		}
		a, b, err := channelRouteMatch(m, table, iface.Index)
		if err != nil {
			return false, false, err
		}
		normal, blackhole = normal || a, blackhole || b
	}
	return normal, blackhole, nil
}

func channelRouteMatch(m syscall.NetlinkMessage, table, index int) (bool, bool, error) {
	if len(m.Data) < unix.SizeofRtMsg {
		return false, false, fmt.Errorf("short route")
	}
	r := m.Data
	if r[0] != unix.AF_INET || r[1] != 0 {
		return false, false, nil
	}
	attrs, err := syscall.ParseNetlinkRouteAttr(&m)
	if err != nil {
		return false, false, err
	}
	t, oif := uint32(r[4]), uint32(0)
	for _, a := range attrs {
		switch a.Attr.Type {
		case unix.RTA_TABLE, unix.RTA_OIF:
			if len(a.Value) != 4 {
				return false, false, fmt.Errorf("invalid route attribute")
			}
			v := binary.NativeEndian.Uint32(a.Value)
			if a.Attr.Type == unix.RTA_TABLE {
				t = v
			} else {
				oif = v
			}
		}
	}
	if t != uint32(table) {
		return false, false, nil
	}
	return r[7] == unix.RTN_UNICAST && oif == uint32(index), r[7] == unix.RTN_BLACKHOLE, nil
}
