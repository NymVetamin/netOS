package apply

import (
	"context"
	"net/netip"
)

type managementKey struct{}
type managementConnection struct{ remote, local netip.Addr }

// WithManagementConnection carries socket endpoints, never user-supplied
// forwarded headers. Unknown endpoints must not grant a confirmation exemption.
func WithManagementConnection(ctx context.Context, remote, local netip.Addr) context.Context {
	return context.WithValue(ctx, managementKey{}, managementConnection{remote.Unmap(), local.Unmap()})
}

func ManagementConnection(ctx context.Context) (remote, local netip.Addr) {
	c, _ := ctx.Value(managementKey{}).(managementConnection)
	return c.remote, c.local
}
