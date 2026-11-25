package multiwan

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestBalanceKernelSnapshotRuleGroups(t *testing.T) {
	ctx := context.Background()
	rules := " 30003: second \n 30001: first\n30001: first\n030001: ignore\n30001 : ignore\n300010: ignore\n30003:second:tail"
	failure := errors.New("route read failed")
	fail := false
	r := &responseRunner{respond: func(cmd string) (string, error) {
		switch cmd {
		case "ip -4 rule show":
			return rules, nil
		case "ip -4 route show table 3001":
			return "", errors.New("FIB table does not exist")
		case "ip -4 route show table 3003":
			if fail {
				return "", failure
			}
			return "blackhole default\n", nil
		default:
			t.Fatalf("unexpected command %q", cmd)
			return "", nil
		}
	}}
	c := New(r, t.TempDir(), nil)
	indices := map[int]bool{3: true, 1: true}
	want := []balanceKernelSnapshot{{index: 1, rule: "30001: first\n30001: first\n"}, {index: 3, routes: "blackhole default\n", rule: "30003: second\n30003:second:tail\n"}}
	check := func() {
		t.Helper()
		r.commands = nil
		got, err := c.captureBalanceKernel(ctx, indices)
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("got %#v, %v; want %#v", got, err, want)
		}
		if !slices.Equal(r.commands, []string{"ip -4 rule show", "ip -4 route show table 3001", "ip -4 route show table 3003"}) {
			t.Fatal(r.commands)
		}
	}
	check()
	rules = ""
	want[0].rule = ""
	want[1].rule = ""
	check()
	fail = true
	if got, err := c.captureBalanceKernel(ctx, indices); got != nil || !errors.Is(err, failure) {
		t.Fatalf("failure: %#v, %v", got, err)
	}
}

// Таблица аплинка без кабеля печатается с linkdown, а iproute2 этот флаг на
// входе отвергает: откат балансировки не возвращал маршрут.
func TestRestoreBalanceReplaysLinkdownRoute(t *testing.T) {
	r := &responseRunner{respond: func(cmd string) (string, error) {
		if strings.Contains(cmd, "linkdown") {
			return "", errors.New(`Error: either "to" is duplicate, or "linkdown" is a garbage.`)
		}
		return "", nil
	}}
	c := New(r, t.TempDir(), nil)
	snapshot := []balanceKernelSnapshot{{index: 2, routes: "default via 192.0.2.1 dev va linkdown\n"}}
	if err := c.restoreBalance(context.Background(), snapshot, t.TempDir()+"/owned", balanceOwnedSnapshot{}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.commands, "ip -4 route replace default via 192.0.2.1 dev va table 3002") {
		t.Fatal(r.commands)
	}
}

func BenchmarkCaptureBalanceKernel(b *testing.B) {
	for _, size := range []int{2, 128} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			var rules strings.Builder
			indices := map[int]bool{}
			for i := 1; i <= size; i++ {
				indices[i] = true
				for j := 0; j < 8; j++ {
					fmt.Fprintf(&rules, "%d: from all lookup %d\n", priorityBase+i, tableBase+i)
				}
				fmt.Fprintf(&rules, "%d: unrelated\n", i)
			}
			output := rules.String()
			r := &responseRunner{respond: func(cmd string) (string, error) {
				if cmd == "ip -4 rule show" {
					return output, nil
				}
				return "blackhole default\n", nil
			}}
			c := New(r, b.TempDir(), nil)
			for b.Loop() {
				r.commands = r.commands[:0]
				snapshots, err := c.captureBalanceKernel(context.Background(), indices)
				if err != nil || len(snapshots) != size || len(r.commands) != 1+size {
					b.Fatal(err)
				}
			}
		})
	}
}
