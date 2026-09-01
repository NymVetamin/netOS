//go:build linux

package multiwan

import (
	"context"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func probeTCP(ctx context.Context, iface, address string, timeout time.Duration) error {
	dialer := net.Dialer{Timeout: timeout}
	if iface != "" {
		dialer.Control = func(_, _ string, raw syscall.RawConn) error {
			var sockErr error
			if err := raw.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
			}); err != nil {
				return err
			}
			return sockErr
		}
	}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	return conn.Close()
}
