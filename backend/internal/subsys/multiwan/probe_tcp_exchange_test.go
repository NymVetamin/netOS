package multiwan

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestTCPProbeChecksApplicationResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 4)
				if _, err := conn.Read(buf); err == nil && string(buf) == "PING" {
					_, _ = conn.Write([]byte("PONG"))
				}
			}()
		}
	}()
	if err := probeTCPExchange(context.Background(), "", listener.Addr().String(), time.Second, "PING", "PONG"); err != nil {
		t.Fatal(err)
	}
	if err := probeTCPExchange(context.Background(), "", listener.Addr().String(), time.Second, "PING", "FAIL"); err == nil {
		t.Fatal("wrong response accepted")
	}
}
