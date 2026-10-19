package api

import (
	"context"
	"sync"
	"time"

	"github.com/netos-router/netos/internal/config"
)

// Coalesce overlapping panel polls only. Apply/takeover checks still call the
// subsystem directly. Engine.Current publishes a new config pointer on changes.
type networkConflictCache struct {
	mu     sync.Mutex
	config *config.Config
	at     time.Time
	rows   []string
}

func (s *Server) networkConflictsSnapshot(ctx context.Context, cfg *config.Config) []string {
	cache := &s.networkConflictStatus
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.config == cfg && !cache.at.IsZero() && time.Since(cache.at) < time.Second {
		return append([]string(nil), cache.rows...)
	}
	rows := s.NetworkConflicts.IfupdownConflicts(ctx, cfg)
	if ctx.Err() == nil {
		cache.config, cache.at, cache.rows = cfg, time.Now(), append([]string(nil), rows...)
	}
	return rows
}
