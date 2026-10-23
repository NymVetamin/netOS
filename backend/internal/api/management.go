package api

import (
	"context"
	"net"
	"net/http"
	"net/netip"

	"github.com/netos-router/netos/internal/apply"
)

func managementContext(ctx context.Context, r *http.Request) context.Context {
	// A known proxy hop is not proof of the browser's management path.
	if r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Real-IP") != "" {
		return ctx
	}
	remote, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return ctx
	}
	local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return ctx
	}
	addr, err := netip.ParseAddrPort(local.String())
	if err != nil {
		return ctx
	}
	return apply.WithManagementConnection(ctx, remote.Addr(), addr.Addr())
}
