package channels

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestOpenConnectWaitsForConfiguredTunnelBeforeRoutes(t *testing.T) {
	s, _ := newTestSubsystem(t)
	base := &serviceLifecycleRunner{s: s, active: map[string]bool{}, enabled: map[string]bool{}, routes: map[string]string{}}
	states := []string{
		`[]`,
		`[{"flags":["POINTOPOINT"],"addr_info":[]}]`,
		`[{"flags":["UP","POINTOPOINT"],"addr_info":[]}]`,
		`[{"flags":["UP","POINTOPOINT"],"addr_info":[{"family":"inet","local":"203.0.113.177"}]}]`,
	}
	checks := 0
	s.Runner = channelRunnerFunc(func(ctx context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		if command == "ip -j -4 addr show dev tun-ch3" {
			index := checks
			if index >= len(states) {
				index = len(states) - 1
			}
			checks++
			return states[index], nil
		}
		if strings.Contains(command, "route replace default") && checks < len(states) {
			t.Fatal("route installed before the connect script brought up and addressed the TUN")
		}
		return base.Run(ctx, name, args...)
	})
	if _, err := s.applyOpenConnect(context.Background(), serviceTestChannel("openconnect"), false, true); err != nil {
		t.Fatal(err)
	}
	if checks < len(states) || !strings.Contains(base.routes["1003"], "default dev tun-ch3") {
		t.Fatalf("readiness checks=%d, routes=%q", checks, base.routes["1003"])
	}
}

func TestOpenConnectReadinessRejectsIncompleteState(t *testing.T) {
	for _, state := range []string{"", `bad JSON`, `[]`, `[{"flags":[],"addr_info":[{"family":"inet","local":"203.0.113.177"}]}]`, `[{"flags":["UP"],"addr_info":[{"family":"inet6","local":"::1"}]}]`} {
		t.Run(state, func(t *testing.T) {
			s, _ := newTestSubsystem(t)
			s.Runner = channelRunnerFunc(func(context.Context, string, ...string) (string, error) { return state, nil })
			if s.openConnectReady(context.Background(), "tun-ch3") {
				t.Fatal("incomplete tunnel reported ready")
			}
		})
	}
}

func TestOpenConnectReadinessCancellationCleansNewTunnel(t *testing.T) {
	s, _ := newTestSubsystem(t)
	base := &serviceLifecycleRunner{s: s, active: map[string]bool{}, enabled: map[string]bool{}, routes: map[string]string{}}
	s.Runner = channelRunnerFunc(func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "ip" && strings.Join(args, " ") == "-j -4 addr show dev tun-ch3" {
			return "", errors.New("not ready")
		}
		return base.Run(ctx, name, args...)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := s.applyOpenConnect(ctx, serviceTestChannel("openconnect"), false, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if s.linkExists("tun-ch3") {
		t.Fatal("cancelled startup left a new tunnel")
	}
}
