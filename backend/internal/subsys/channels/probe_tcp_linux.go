//go:build linux

package channels

import (
	"context"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// probeTCP only tests whether the TCP handshake succeeds. curl's telnet
// handler waits for application data and therefore reports a healthy silent
// service as a timeout. SO_BINDTODEVICE keeps the check inside the channel.
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
	return confirmTCPHandshake(conn, timeout)
}
