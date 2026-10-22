//go:build linux

package system

import (
	"context"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"syscall"
)

// kernelDump rejects incomplete snapshots rather than returning partial counters.
func kernelDump(ctx context.Context, protocol int, req []byte) ([]syscall.NetlinkMessage, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "netos-netlink")
	defer f.Close()
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { f.Close() })
	defer stop()
	var sendErr error
	err = raw.Control(func(fd uintptr) {
		sendErr = unix.Sendto(int(fd), req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
	})
	if err != nil {
		return nil, err
	}
	if sendErr != nil {
		return nil, sendErr
	}
	buf := make([]byte, 64*1024)
	var result []syscall.NetlinkMessage
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
			return nil, ctx.Err()
		}
		if err != nil {
			return nil, err
		}
		if recvErr != nil {
			return nil, recvErr
		}
		if n == 0 || flags&unix.MSG_TRUNC != 0 {
			return nil, fmt.Errorf("truncated route dump")
		}
		from, ok := sender.(*unix.SockaddrNetlink)
		if !ok || from.Pid != 0 {
			return nil, fmt.Errorf("unexpected route sender")
		}
		messages, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range messages {
			if m.Header.Seq != 1 || m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				return nil, fmt.Errorf("incomplete route dump")
			}
			switch m.Header.Type {
			case unix.NLMSG_OVERRUN:
				return nil, fmt.Errorf("route dump overrun")
			case unix.NLMSG_ERROR:
				if len(m.Data) >= 4 && binary.NativeEndian.Uint32(m.Data) == 0 {
					if binary.NativeEndian.Uint16(req[6:])&unix.NLM_F_DUMP == 0 {
						return result, nil
					}
					continue
				}
				return nil, fmt.Errorf("route dump error: %x", m.Data)
			case unix.NLMSG_DONE:
				if len(m.Data) >= 4 && binary.NativeEndian.Uint32(m.Data) != 0 {
					return nil, fmt.Errorf("failed route dump")
				}
				return result, nil
			default:
				m.Data = append([]byte(nil), m.Data...)
				result = append(result, m)
			}
		}
	}
}
