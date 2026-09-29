package services

import (
	"context"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestDHCPChangesDoNotRequireConnectivityConfirmation(t *testing.T) {
	for _, mode := range []string{"enable", "disable", "provider"} {
		t.Run(mode, func(t *testing.T) {
			old, next := config.Default(), config.Default()
			old.DHCP.Enabled, next.DHCP.Enabled = true, true
			switch mode {
			case "enable":
				old.DHCP.Enabled = false
			case "disable":
				next.DHCP.Enabled = false
			case "provider":
				next.DHCP.Provider = "isc-dhcp-server"
			}
			actions, err := NewDHCP(nil).Plan(old, next)
			if err != nil || len(actions) != 1 {
				t.Fatalf("actions=%v err=%v", actions, err)
			}
			if actions[0].Disruptive {
				t.Fatalf("DHCP-only %s requires connectivity confirmation", mode)
			}
		})
	}
}

func TestDNSChangesDoNotRequireConnectivityConfirmation(t *testing.T) {
	for _, mode := range []string{"enable", "disable", "provider"} {
		t.Run(mode, func(t *testing.T) {
			old, next := config.Default(), config.Default()
			old.DNS.Enabled, next.DNS.Enabled = true, true
			switch mode {
			case "enable":
				old.DNS.Enabled = false
			case "disable":
				next.DNS.Enabled = false
			case "provider":
				next.DNS.Provider = "unbound"
			}
			actions := NewDNS(nil).planProvider(context.Background(), old, next)
			if len(actions) != 1 || actions[0].Disruptive {
				t.Fatalf("DNS-only %s requires connectivity confirmation: %v", mode, actions)
			}
		})
	}
}
