package routing

import (
	"errors"
	"testing"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
)

func TestEmptyTableConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name, command, out string
		fail, safe         bool
	}{
		{name: "empty", safe: true},
		{name: "kernel IPv4 route", command: "ip -4 route show table all", out: "blackhole 192.0.2.0/24 table 209"},
		{name: "kernel IPv6 route", command: "ip -6 route show table all", out: "unreachable 2001:db8::/32 table qa-empty"},
		{name: "kernel rule", command: "ip -4 rule show", out: "12345: from all lookup 209"},
		{name: "kernel IPv6 rule", command: "ip -6 rule show", out: "12345: from all lookup qa-empty"},
		{name: "unrelated repair", command: "ip -4 route show table all proto static", out: "blackhole 192.0.2.0/24 table 200"},
		{name: "read failure", command: "ip -6 rule show", fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old, next := config.Default(), config.Default()
			next.Routing.Tables = []config.RouteTable{{Name: "qa-empty", Number: 209}}
			response := runnerResponse{out: tc.out}
			if tc.fail {
				response.err = errors.New("unavailable")
			}
			s := New(&recordingRunner{responses: map[string]runnerResponse{tc.command: response}})
			for _, pair := range [][2]*config.Config{{old, next}, {next, old}} {
				actions, err := s.Plan(pair[0], pair[1])
				if err != nil || len(actions) != 1 {
					t.Fatalf("plan: %v %v", actions, err)
				}
				if safe := actions[0].Confirmation == apply.ConfirmationSafe; safe != tc.safe {
					t.Fatalf("safe=%v want %v", safe, tc.safe)
				}
			}
		})
	}
}

func TestTableReferencedInConfigKeepsConfirmation(t *testing.T) {
	old, next := config.Default(), config.Default()
	old.Routing.Tables = []config.RouteTable{{Name: "old-name", Number: 209}}
	next.Routing.Tables = []config.RouteTable{{Name: "new-name", Number: 209}}
	for _, name := range []string{"old-name", "209"} {
		old.Routing.Rules = []config.RouteRule{{Enabled: true, Priority: 20100, Table: name}}
		next.Routing.Rules = old.Routing.Rules
		actions, err := New(&recordingRunner{}).Plan(old, next)
		if err != nil || len(actions) != 1 || actions[0].Confirmation == apply.ConfirmationSafe {
			t.Fatalf("referenced table safe: %v %v", actions, err)
		}
	}
}
