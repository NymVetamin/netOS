package api

import (
	"context"
	"testing"

	"golang.org/x/crypto/acme/autocert"
)

func TestACMEHTTPHostWithPort(t *testing.T) {
	m, err := newProductionACMEManager(t.TempDir(), "panel.example.com", "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	policy := m.(*autocert.Manager).HostPolicy
	for _, host := range []string{"panel.example.com", "panel.example.com:80"} {
		if err := policy(context.Background(), host); err != nil {
			t.Errorf("configured host %s rejected: %v", host, err)
		}
	}
	for _, host := range []string{"other.example.com:80", "panel.example.com.evil:80", "panel.example.com:80:90"} {
		if err := policy(context.Background(), host); err == nil {
			t.Errorf("unconfigured host %s allowed", host)
		}
	}
}
