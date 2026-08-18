package services

import (
	"context"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

type serviceRunner struct{ commands []string }

func (r *serviceRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.commands = append(r.commands, name+" "+strings.Join(args, " "))
	return "", nil
}

func (r *serviceRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestDisabledDNSDoesNotApplyUnsupportedProvider(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.Provider = "unbound"
	cfg.DNS.Enabled = false
	if err := NewDNS(NewManager(&serviceRunner{})).Apply(context.Background(), cfg); err != nil {
		t.Fatalf("выключенный DNS не должен применять provider: %v", err)
	}
}

func TestStopUnusedDisablesProvidersWhoseFeatureIsOff(t *testing.T) {
	runner := &serviceRunner{}
	m := NewManager(runner)
	cfg := config.Default()
	cfg.DHCP.Provider = "isc-dhcp-server"
	cfg.DNS.Provider = "unbound"
	m.stopUnused(context.Background(), cfg)
	joined := strings.Join(runner.commands, "\n")
	for _, unit := range []string{"isc-dhcp-server.service", "kea-dhcp4-server.service", "unbound.service"} {
		if !strings.Contains(joined, unit) {
			t.Fatalf("не отключён %s; команды:\n%s", unit, joined)
		}
	}
}
