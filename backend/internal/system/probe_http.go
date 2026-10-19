package system

import (
	"context"
	"fmt"
	"time"
)

// ProbeHTTP uses a native probe when the runner supports it. Other runners keep
// the command operation, including its cancellation and error handling.
func ProbeHTTP(ctx context.Context, runner Runner, iface, target string, timeout time.Duration) error {
	if p, ok := runner.(interface {
		ProbeHTTP(context.Context, string, string, time.Duration) error
	}); ok {
		return p.ProbeHTTP(ctx, iface, target, timeout)
	}
	return curlProbeHTTP(ctx, runner, iface, target, timeout)
}

func curlProbeHTTP(ctx context.Context, runner Runner, iface, target string, timeout time.Duration) error {
	_, err := runner.Run(ctx, "curl", "--interface", iface, "--fail", "--silent", "--max-time", fmt.Sprint(timeout.Seconds()), target)
	return err
}
