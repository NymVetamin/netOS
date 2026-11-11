package amneziawg

import (
	"context"
	"fmt"
	"strings"
)

// WireGuardControl leaves the kernel tool unchanged. AWG requests use the
// local socket in-process, avoiding a netosd subprocess on every status poll.
func WireGuardControl(ctx context.Context, r interface {
	Run(context.Context, string, ...string) (string, error)
}, protocol string, args ...string) (string, error) {
	if protocol != "amneziawg" {
		return r.Run(ctx, "wg", args...)
	}
	if len(args) == 0 || args[0] != "show" && args[0] != "syncconf" {
		return "", fmt.Errorf("неподдерживаемая операция управления AmneziaWG")
	}
	var out strings.Builder
	err := Execute(ctx, args, &out)
	return out.String(), err
}
