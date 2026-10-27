//go:build !linux

package services

import "context"

// netOS networking runs on Linux. Keep non-Linux development builds idle.
func subscribeIPv4Links(ctx context.Context) (<-chan error, error) {
	events := make(chan error)
	go func() { <-ctx.Done(); close(events) }()
	return events, nil
}
