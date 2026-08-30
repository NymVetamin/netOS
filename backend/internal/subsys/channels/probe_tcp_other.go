//go:build !linux

package channels

import (
	"context"
	"net"
	"time"
)

func probeTCP(ctx context.Context, _ string, address string, timeout time.Duration) error {
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp4", address)
	if err != nil {
		return err
	}
	return conn.Close()
}
