package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/netos-router/netos/internal/apply"
)

func TestManagementContextUsesSocketAndSurvivesDetach(t *testing.T) {
	for _, header := range []string{"", "Forwarded", "X-Forwarded-For", "X-Real-IP"} {
		t.Run(header, func(t *testing.T) {
			requestCtx, cancel := context.WithCancel(context.WithValue(context.Background(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 80}))
			r := httptest.NewRequest("POST", "/api/config/apply", nil).WithContext(requestCtx)
			r.RemoteAddr = "192.0.2.2:1234"
			if header != "" {
				r.Header.Set(header, "198.51.100.5")
			}
			ctx := managementContext(context.Background(), r)
			cancel()
			remote, local := apply.ManagementConnection(ctx)
			if ctx.Err() != nil {
				t.Fatal("apply context inherits request cancellation")
			}
			if header != "" {
				if remote.IsValid() || local.IsValid() {
					t.Fatal("proxy granted direct connection context")
				}
				return
			}
			if remote.String() != "192.0.2.2" || local.String() != "192.0.2.1" {
				t.Fatalf("endpoints %v %v", remote, local)
			}
		})
	}
	r := httptest.NewRequest("GET", "/api/config/plan", nil)
	remote, _ := apply.ManagementConnection(managementContext(context.Background(), r))
	if remote.IsValid() {
		t.Fatal("missing local socket granted context")
	}
}
