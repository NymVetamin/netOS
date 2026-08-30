package channels

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestProbeTCPOnlyRequiresHandshake(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := probeTCP(ctx, "", listener.Addr().String(), time.Second); err != nil {
		t.Fatalf("silent TCP listener was reported down: %v", err)
	}
	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-ctx.Done():
		t.Fatal("probe did not reach listener")
	}
}
