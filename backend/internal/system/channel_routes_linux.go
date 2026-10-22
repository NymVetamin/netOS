//go:build linux

package system

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
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
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return false, false, err
	}
	f := os.NewFile(uintptr(fd), "channel-routes")
	defer f.Close()
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return false, false, err
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return false, false, err
	}
	stop := context.AfterFunc(ctx, func() { f.Close() })
	defer stop()
	req := make([]byte, unix.NLMSG_HDRLEN+unix.SizeofRtMsg)
	binary.NativeEndian.PutUint32(req, uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:], unix.RTM_GETROUTE)
	binary.NativeEndian.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(req[8:], 1)
	req[unix.NLMSG_HDRLEN] = unix.AF_INET
	var sendErr error
	err = raw.Control(func(fd uintptr) {
		sendErr = unix.Sendto(int(fd), req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
	})
	if err != nil {
		return false, false, err
	}
	if sendErr != nil {
		return false, false, sendErr
	}
	buf := make([]byte, 64*1024)
	var normal, blackhole bool
	for {
		var n, flags int
		var sender unix.Sockaddr
		var recvErr error
		err = raw.Read(func(fd uintptr) bool {
			for {
				n, _, flags, sender, recvErr = unix.Recvmsg(int(fd), buf, nil, 0)
				if recvErr != unix.EINTR {
					break
				}
			}
			return recvErr != unix.EAGAIN && recvErr != unix.EWOULDBLOCK
		})
		if ctx.Err() != nil {
			return false, false, ctx.Err()
		}
		if err != nil {
			return false, false, err
		}
		if recvErr != nil {
			return false, false, recvErr
		}
		if n == 0 || flags&unix.MSG_TRUNC != 0 {
			return false, false, fmt.Errorf("truncated route dump")
		}
		from, ok := sender.(*unix.SockaddrNetlink)
		if !ok || from.Pid != 0 {
			return false, false, fmt.Errorf("unexpected route sender")
		}
		messages, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return false, false, err
		}
		for _, m := range messages {
			if m.Header.Seq != 1 || m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				return false, false, fmt.Errorf("incomplete route dump")
			}
			switch m.Header.Type {
			case unix.NLMSG_OVERRUN:
				return false, false, fmt.Errorf("route dump overrun")
			case unix.NLMSG_ERROR:
				return false, false, fmt.Errorf("route dump error: %x", m.Data)
			case unix.NLMSG_DONE:
				if len(m.Data) >= 4 && binary.NativeEndian.Uint32(m.Data) != 0 {
					return false, false, fmt.Errorf("failed route dump")
				}
				return normal, blackhole, nil
			case unix.RTM_NEWROUTE:
				a, b, err := channelRouteMatch(m, table, iface.Index)
				if err != nil {
					return false, false, err
				}
				normal, blackhole = normal || a, blackhole || b
			}
		}
	}
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
