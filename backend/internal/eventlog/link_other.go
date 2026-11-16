//go:build !linux

package eventlog

import "context"

// WatchLinks needs rtnetlink; other systems report nothing.
func WatchLinks(ctx context.Context, log *Log, watched func(name string) bool) {}
