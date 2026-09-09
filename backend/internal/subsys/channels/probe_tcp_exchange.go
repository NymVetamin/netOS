package channels

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

func probeTCP(ctx context.Context, iface, address string, timeout time.Duration) error {
	conn, err := dialProbeTCP(ctx, iface, address, timeout)
	if err != nil {
		return err
	}
	return confirmTCPHandshake(conn, timeout)
}

// A userspace TUN can acknowledge TCP locally. Only the configured application
// response is evidence that the remote service actually exchanged data.
func probeTCPExchange(ctx context.Context, iface, address string, timeout time.Duration, request, response string) error {
	if response == "" || len(response) > 4096 || len(request) > 4096 {
		return fmt.Errorf("invalid TCP response probe")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dialProbeTCP(ctx, iface, address, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err := io.Copy(conn, strings.NewReader(request)); err != nil {
		return err
	}
	got := make([]byte, len(response))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if string(got) != response {
		return fmt.Errorf("TCP response prefix did not match")
	}
	return nil
}
