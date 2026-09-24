package netconf

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type handoverRunner struct {
	commands      []string
	failRoute     bool
	missingBridge bool
}

func (r *handoverRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.commands = append(r.commands, name+" "+strings.Join(args, " "))
	if r.failRoute && name == "ip" && len(args) > 2 && args[0] == "route" && args[1] == "add" {
		return "", errors.New("route failure")
	}
	if name == "ip" && len(args) >= 4 && args[0] == "-j" {
		if len(args) > 4 && args[len(args)-1] == "lo" {
			return `[{"addr_info":[{"local":"127.0.0.1","prefixlen":8}]}]`, nil
		}
		if r.missingBridge && args[len(args)-1] == "br-lan" {
			return "", errors.New(`Device "br-lan" does not exist`)
		}
		return `[{"addr_info":[{"local":"192.0.2.1","prefixlen":24}]}]`, nil
	}
	return "", nil
}

func TestLANHandoverCleansUpIfRouteCreationFails(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "eth2", Type: "physical", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "lan", Interface: "lan", RouterAddress: "192.0.2.1/24", Enabled: true}}
	r := &handoverRunner{failRoute: true}
	_, err := New(r, nil).protectLANAddresses(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "route failure") {
		t.Fatalf("expected route error, got %v", err)
	}
	commands := strings.Join(r.commands, "\n")
	for _, want := range []string{
		"ip address del 192.0.2.1/32 dev lo",
		"ip address del 198.19.255.254/32 dev eth2",
	} {
		if !strings.Contains(commands, want) {
			t.Fatalf("missing cleanup %q:\n%s", want, commands)
		}
	}
}

func TestLANHandoverSkipsNewBridge(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "br-lan", Type: "bridge", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "lan", Interface: "lan", RouterAddress: "192.0.2.1/24", Enabled: true}}
	r := &handoverRunner{missingBridge: true}
	guard, err := New(r, nil).protectLANAddresses(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(guard.items) != 0 {
		t.Fatalf("new bridge should need no guard: items=%v", guard.items)
	}
}

func (r *handoverRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestLANHandoverProtectsAndRestoresGateway(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{{ID: "lan", Name: "eth2", Type: "physical", Enabled: true}}
	cfg.Networks = []config.Network{{ID: "lan", Interface: "lan", RouterAddress: "192.0.2.1/24", Enabled: true}}
	r := &handoverRunner{}
	s := New(r, nil)
	guard, err := s.protectLANAddresses(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(guard.items) != 1 {
		t.Fatalf("protected segments=%d, want 1", len(guard.items))
	}
	if err := guard.close(context.Background()); err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(r.commands, "\n")
	for _, want := range []string{
		"ip address add 198.19.255.254/32 dev eth2",
		"ip address add 192.0.2.1/32 dev lo",
		"ip route add 192.0.2.0/24 dev eth2 src 192.0.2.1 proto 203 metric 32760",
		"ip route del 192.0.2.0/24 dev eth2 proto 203 metric 32760",
		"ip address del 192.0.2.1/32 dev lo",
		"ip address del 198.19.255.254/32 dev eth2",
	} {
		if !strings.Contains(commands, want) {
			t.Fatalf("missing %q in handover commands:\n%s", want, commands)
		}
	}
}
