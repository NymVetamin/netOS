//go:build !linux

package channels

import (
	"context"
	"net"
	"time"
)

func dialProbeTCP(ctx context.Context, _ string, address string, timeout time.Duration) (net.Conn, error) {
	return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", address)
}
