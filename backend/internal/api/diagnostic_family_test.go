package api

import (
	"reflect"
	"slices"
	"testing"
)

func TestDiagnosticTargetFamily(t *testing.T) {
	for _, kind := range []string{"ping", "traceroute", "mtr", "iperf"} {
		for _, tc := range []struct{ host, family, target string }{
			{"192.0.2.1", "-4", "192.0.2.1"},
			{"example.test", "-4", "example.test"},
			{"2001:db8::1", "-6", "2001:db8::1"},
			{"::1", "-6", "::1"},
			{"::ffff:192.0.2.1", "-4", "192.0.2.1"},
		} {
			t.Run(kind+"/"+tc.host, func(t *testing.T) {
				in := diagnosticInput{Kind: kind, Host: tc.host, Count: 1, TTL: 3, Duration: 2, Mbps: 1, UDP: true, Reverse: true}
				got, err := buildDiagnosticCommand(in)
				if err != nil {
					t.Fatal(err)
				}
				if got.args[0] != tc.family || !slices.Contains(got.args, tc.target) {
					t.Fatalf("wrong family/target: %v", got.args)
				}
				again, err := buildDiagnosticCommand(in)
				if err != nil || !reflect.DeepEqual(got, again) {
					t.Fatal("repeat changed command")
				}
				in.Host = "192.0.2.1"
				v4, err := buildDiagnosticCommand(in)
				if err != nil {
					t.Fatal(err)
				}
				want := append([]string(nil), v4.args...)
				want[0] = tc.family
				for i := range want {
					if want[i] == "192.0.2.1" {
						want[i] = tc.target
					}
				}
				if !reflect.DeepEqual(want, got.args) || got.duration != v4.duration || got.name != v4.name {
					t.Fatalf("unrelated options changed: %v vs %v", got, v4)
				}
			})
		}
	}
	if _, err := buildDiagnosticCommand(diagnosticInput{Kind: "iperf", Host: "::1", Bind: "127.0.0.1"}); err == nil {
		t.Error("mixed address families accepted")
	}
	if _, err := buildDiagnosticCommand(diagnosticInput{Kind: "route", Host: "::1"}); err == nil {
		t.Error("IPv4 route contract changed")
	}
	if _, err := buildDiagnosticCommand(diagnosticInput{Kind: "dns", Host: "::1", QueryType: "PTR"}); err != nil {
		t.Fatal("DNS literal rejected", err)
	}
}
