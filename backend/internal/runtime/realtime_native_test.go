package runtime

import (
	"context"
	"errors"
	"testing"
)

type nativeCountersRunner struct {
	failed   bool
	commands int
}

func (r *nativeCountersRunner) NFTSetCounters(context.Context, string) (map[string]map[string]uint64, error) {
	if r.failed {
		return nil, errors.New("interrupted dump")
	}
	return map[string]map[string]uint64{"up4": {"192.0.2.1": 10}, "down4": {"192.0.2.1": 20}, "up6": {"2001:db8::1": 30}, "down6": {}}, nil
}
func (r *nativeCountersRunner) Run(context.Context, string, ...string) (string, error) {
	r.commands++
	return `{"nftables":[{"set":{"name":"up4","elem":[{"elem":{"val":"192.0.2.1","counter":{"bytes":99}}}]}}]}`, nil
}
func (r *nativeCountersRunner) RunInput(context.Context, string, string, ...string) (string, error) {
	panic("unexpected mutation")
}
func TestRealtimeNativeCountersAndFallback(t *testing.T) {
	r := &nativeCountersRunner{}
	h := &ClientHistory{Runner: r}
	counts, err := h.RealtimeCounters(context.Background())
	if err != nil || r.commands != 0 || counts["192.0.2.1"].TX != 10 || counts["192.0.2.1"].RX != 20 || counts["2001:db8::1"].TX != 30 {
		t.Fatalf("native: %v %v commands=%d", counts, err, r.commands)
	}
	r.failed = true
	counts, err = h.RealtimeCounters(context.Background())
	if err != nil || r.commands != 1 || counts["192.0.2.1"].TX != 99 {
		t.Fatalf("fallback: %v %v commands=%d", counts, err, r.commands)
	}
}
