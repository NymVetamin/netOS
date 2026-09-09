package channels

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

func TestTCPExchangeRequiresRemoteResponse(t *testing.T) {
	for _, tc := range []struct {
		name, request, reply, expected string
		silent, pass                   bool
	}{
		{"request and fragmented response", "ping\n", "pong\nmore", "pong\n", false, true},
		{"server greeting", "", "SSH-2.0-fixture\r\n", "SSH-2.0-", false, true},
		{"wrong response", "ping\n", "error\n", "pong\n", false, false},
		{"truncated response", "ping\n", "pon", "pong\n", false, false},
		{"silent local acceptance", "", "", "pong\n", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				request := make([]byte, len(tc.request))
				if _, err := io.ReadFull(conn, request); err != nil {
					done <- err
					return
				}
				if string(request) != tc.request {
					done <- io.ErrUnexpectedEOF
					return
				}
				if tc.silent {
					_, _ = io.Copy(io.Discard, conn)
				} else {
					for _, b := range []byte(tc.reply) {
						if _, err := conn.Write([]byte{b}); err != nil {
							break
						}
					}
				}
				done <- nil
			}()
			err = probeTCPExchange(context.Background(), "", listener.Addr().String(), 200*time.Millisecond, tc.request, tc.expected)
			if (err == nil) != tc.pass {
				t.Fatalf("success=%v, want %v: %v", err == nil, tc.pass, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTCPExchangeCancellationAndLimits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := probeTCPExchange(ctx, "", "127.0.0.1:1", time.Hour, "", "reply"); err == nil {
		t.Fatal("canceled probe succeeded")
	}
	for _, response := range []string{"", strings.Repeat("x", 4097)} {
		if err := probeTCPExchange(context.Background(), "", "not-an-address", time.Second, "", response); err == nil {
			t.Fatal("invalid response accepted")
		}
	}
}

func TestXrayLegacyTCPProbeFailsClosed(t *testing.T) {
	s := &Subsystem{}
	ch := config.Channel{Type: "xray", Probe: config.Probe{Type: "tcp", Targets: []string{"127.0.0.1:1"}}}
	if s.probe(context.Background(), ch, "") {
		t.Fatal("Xray TCP without a response contract was healthy")
	}
}

func TestTCPExchangeCancelsAnEstablishedSilentConnection(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- probeTCPExchange(ctx, "", listener.Addr().String(), time.Minute, "", "reply") }()
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled silent connection reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("probe ignored cancellation after TCP connection establishment")
	}
}
