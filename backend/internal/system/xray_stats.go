package system

import "context"

// XrayUserStats returns the same JSON consumed from xray api statsonlineiplist.
// Native runners avoid starting a second Go runtime for each telemetry sample.
func XrayUserStats(ctx context.Context, runner Runner, socket string) (string, error) {
	if native, ok := runner.(interface {
		XrayUserStats(context.Context, string) (string, error)
	}); ok {
		return native.XrayUserStats(ctx, socket)
	}
	return runner.Run(ctx, "/usr/local/bin/xray", "api", "statsonlineiplist", "--server=unix://"+socket, "--timeout=3", "-all", "-include-traffic")
}
