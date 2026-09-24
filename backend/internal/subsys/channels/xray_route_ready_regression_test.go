package channels

import (
	"context"
	"errors"
	"testing"
)

func TestChannelRouteWaitsForTunUp(t *testing.T) {
	attempts := 0
	s := &Subsystem{Runner: channelRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		attempts++
		if attempts == 1 {
			return "", errors.New("RTNETLINK answers: Device for nexthop is not up")
		}
		return "", nil
	})}
	if err := s.replaceChannelDefaultWhenReady(context.Background(), "tun-ch3", "1003"); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("route attempts = %d, want 2", attempts)
	}
}
