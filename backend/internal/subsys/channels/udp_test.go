package channels

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type udpRefreshRunner struct {
	*channelRunner
	deletes       []string
	failDelete    bool
	entriesRemain bool
}

func (r *udpRefreshRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "conntrack" {
		if args[0] == "-D" {
			r.deletes = append(r.deletes, strings.Join(args, " "))
			if r.failDelete {
				return "", errors.New("injected conntrack deletion failure")
			}
			return "", nil
		}
		if r.entriesRemain {
			return "udp mark=4097", nil
		}
		return "", nil
	}
	return r.channelRunner.Run(ctx, name, args...)
}
func TestRouteChangesRefreshOnlyChannelUDP(t *testing.T) {
	s, base := newTestSubsystem(t)
	r := &udpRefreshRunner{channelRunner: base}
	s.Runner = r
	ch := channelConfig().Channels[1]
	ctx := context.Background()
	for _, table := range []int{1001, 1001, 1002, 1002} {
		if err := s.ensureRuleTable(ctx, ch, table); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.deletes) != 2 {
		t.Fatalf("unchanged route refreshed UDP: %v", r.deletes)
	}
	for range 2 {
		if err := s.removeChannelRule(ctx, ch); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.deletes) != 3 {
		t.Fatalf("direct transition count: %v", r.deletes)
	}
	if err := s.ensureRuleTable(ctx, ch, 1001); err != nil {
		t.Fatal(err)
	}
	if len(r.deletes) != 4 {
		t.Fatalf("return from direct did not refresh: %v", r.deletes)
	}
	for _, command := range r.deletes {
		if command != "-D -f ipv4 -p udp --mark 0x1001" {
			t.Fatalf("unscoped connection cleanup: %s", command)
		}
	}
}
func TestUDPRefreshFailureRetriesWithoutAnotherRouteChange(t *testing.T) {
	s, base := newTestSubsystem(t)
	r := &udpRefreshRunner{channelRunner: base, failDelete: true, entriesRemain: true}
	s.Runner = r
	ch := channelConfig().Channels[1]
	ctx := context.Background()
	if err := s.ensureRuleTable(ctx, ch, 1002); err == nil {
		t.Fatal("retained UDP entries accepted")
	}
	if !strings.Contains(base.rules, "lookup 1002") {
		t.Fatal("expected route installed before refresh")
	}
	r.failDelete = false
	if err := s.ensureRuleTable(ctx, ch, 1002); err != nil {
		t.Fatal(err)
	}
	if err := s.ensureRuleTable(ctx, ch, 1002); err != nil {
		t.Fatal(err)
	}
	if len(r.deletes) != 2 {
		t.Fatalf("pending refresh not retried exactly once: %v", r.deletes)
	}
}
func TestUDPRefreshAcceptsVerifiedEmptyTable(t *testing.T) {
	s, base := newTestSubsystem(t)
	r := &udpRefreshRunner{channelRunner: base, failDelete: true}
	s.Runner = r
	ch := channelConfig().Channels[1]
	for range 2 {
		if err := s.ensureRuleTable(context.Background(), ch, 1001); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.deletes) != 1 {
		t.Fatalf("empty table repeatedly flushed: %v", r.deletes)
	}
}
