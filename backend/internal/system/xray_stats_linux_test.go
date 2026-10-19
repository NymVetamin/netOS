//go:build linux

package system

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/system/xraystats"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func testXraySocket(t *testing.T) string {
	t.Helper()
	// Keep the Unix socket name below the kernel's pathname limit.
	dir, err := os.MkdirTemp("", "netos-stats-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "stats.sock")
}

func serveXrayStats(t *testing.T, socket string, call func(context.Context, *xraystats.GetUsersStatsRequest) (*xraystats.GetUsersStatsResponse, error)) *grpc.Server {
	t.Helper()
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "xray.app.stats.command.StatsService",
		HandlerType: (*interface{})(nil),
		Methods: []grpc.MethodDesc{{MethodName: "GetUsersStats", Handler: func(_ any, ctx context.Context, decode func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
			request := new(xraystats.GetUsersStatsRequest)
			if err := decode(request); err != nil {
				return nil, err
			}
			return call(ctx, request)
		}}},
	}, nil)
	go func() { _ = s.Serve(l) }()
	t.Cleanup(s.Stop)
	return s
}

func TestXrayUserStatsJSONAndConcurrentSamples(t *testing.T) {
	socket := testXraySocket(t)
	var count atomic.Int32
	serveXrayStats(t, socket, func(_ context.Context, req *xraystats.GetUsersStatsRequest) (*xraystats.GetUsersStatsResponse, error) {
		if !req.IncludeTraffic || req.Reset_ {
			return nil, status.Error(codes.InvalidArgument, "wrong telemetry request")
		}
		count.Add(1)
		return &xraystats.GetUsersStatsResponse{Users: []*xraystats.UserStat{{
			Email:   "server/peer",
			Ips:     []*xraystats.OnlineIPEntry{{Ip: "192.0.2.1", LastSeen: 123}, {Ip: "2001:db8::1", LastSeen: 456}},
			Traffic: &xraystats.TrafficUserStat{Uplink: 9007199254740993, Downlink: 123456789},
		}}}, nil
	})
	runner := NewExec()
	runner.OnCommand = func(string, []string) { t.Error("native stats launched a command") }
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := XrayUserStats(context.Background(), runner, socket)
			if err != nil {
				t.Error(err)
				return
			}
			var response struct {
				Users []struct {
					Email   string
					Ips     []struct{ IP string }
					Traffic struct {
						Uplink   string
						Downlink string
					}
				}
			}
			if err = json.Unmarshal([]byte(out), &response); err != nil {
				t.Error(err)
				return
			}
			if len(response.Users) != 1 {
				t.Errorf("users=%s", out)
				return
			}
			u := response.Users[0]
			if u.Email != "server/peer" || len(u.Ips) != 2 || u.Traffic.Uplink != "9007199254740993" || u.Traffic.Downlink != "123456789" {
				t.Errorf("lost identity/counters: %s", out)
			}
		}()
	}
	wg.Wait()
	if count.Load() != 8 {
		t.Fatalf("calls=%d", count.Load())
	}
}

func TestXrayUserStatsSocketRemovalAndReplacement(t *testing.T) {
	socket := testXraySocket(t)
	empty := func(context.Context, *xraystats.GetUsersStatsRequest) (*xraystats.GetUsersStatsResponse, error) {
		return &xraystats.GetUsersStatsResponse{}, nil
	}
	s := serveXrayStats(t, socket, empty)
	e := NewExec()
	e.Timeout = 150 * time.Millisecond
	if out, err := e.XrayUserStats(context.Background(), socket); err != nil || out != "{}" {
		t.Fatalf("empty stats: %q %v", out, err)
	}
	if err := os.Rename(socket, socket+".old"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.XrayUserStats(context.Background(), socket); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("missing socket: %v", err)
	}
	if err := os.Rename(socket+".old", socket); err != nil {
		t.Fatal(err)
	}
	if _, err := e.XrayUserStats(context.Background(), socket); err != nil {
		t.Fatal("restored socket", err)
	}
	s.Stop()
	serveXrayStats(t, socket, func(context.Context, *xraystats.GetUsersStatsRequest) (*xraystats.GetUsersStatsResponse, error) {
		return nil, status.Error(codes.Unavailable, "replacement server")
	})
	if _, err := e.XrayUserStats(context.Background(), socket); status.Code(err) != codes.Unavailable {
		t.Fatalf("replacement not observed: %v", err)
	}
}

func TestXrayUserStatsCancellationAndRPCFailures(t *testing.T) {
	socket := testXraySocket(t)
	serveXrayStats(t, socket, func(ctx context.Context, _ *xraystats.GetUsersStatsRequest) (*xraystats.GetUsersStatsResponse, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	e := NewExec()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := e.XrayUserStats(ctx, socket); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel=%v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation delayed")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := e.XrayUserStats(ctx, socket); status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("RPC deadline=%v", err)
	}
	missing := testXraySocket(t)
	start = time.Now()
	if _, err := e.XrayUserStats(context.Background(), missing); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("default timeout=%v", err)
	}
	if elapsed := time.Since(start); elapsed < 2800*time.Millisecond || elapsed > 4500*time.Millisecond {
		t.Fatalf("default deadline=%s", elapsed)
	}
}
