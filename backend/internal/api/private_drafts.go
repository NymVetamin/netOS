package api

import (
	"context"
	"net/http"
	"time"

	"github.com/netos-router/netos/internal/config"
)

// Panel accounts own their drafts; local root selects an owner explicitly
// before using the same apply handler with administrative privileges.
func usesPrivateDraft(r *http.Request) bool {
	return userOf(r) != "" && (roleOf(r) == "admin" || roleOf(r) == "limited")
}

type privateDraft struct {
	Base    *config.Config
	Config  *config.Config
	Version uint64
}

func (s *Server) clearPrivateDraftLocked(username string) {
	if d := s.privateDrafts[username]; d != nil {
		d.Config = nil
		d.Base = s.Engine.Current()
		d.Version++
	}
}

// Called under draftMu. A changed active config invalidates an unsaved baseline;
// an existing private draft is retained and reports a conflict until discarded.
func (s *Server) privateDraftLocked(username string) *privateDraft {
	if s.privateDrafts == nil {
		s.privateDrafts = map[string]*privateDraft{}
	}
	d := s.privateDrafts[username]
	if d == nil {
		d = &privateDraft{Base: s.Engine.Current(), Version: 1}
		s.privateDrafts[username] = d
	}
	if d.Config == nil && !sameConfig(d.Base, s.Engine.Current()) {
		d.Base = s.Engine.Current()
		d.Version++
	}
	return d
}

func (s *Server) requestConfig(r *http.Request) *config.Config {
	if !usesPrivateDraft(r) {
		return s.currentDraft()
	}
	s.draftMu.Lock()
	defer s.draftMu.Unlock()
	d := s.privateDraftLocked(userOf(r))
	if d.Config != nil {
		return d.Config
	}
	return d.Base
}

func (s *Server) handlePrivateConfig(w http.ResponseWriter, r *http.Request) {
	if s.Engine == nil {
		writeError(w, 503, "конфигурация недоступна")
		return
	}
	s.draftMu.Lock()
	defer s.draftMu.Unlock()
	d := s.privateDraftLocked(userOf(r))
	cfg := d.Config
	if cfg == nil {
		cfg = d.Base
	}
	if cfg == nil {
		writeError(w, 503, "конфигурация ещё не загружена")
		return
	}
	p := r.URL.Path
	if r.Method == http.MethodPut || p == "/api/config/validate" {
		if s.draftApplying {
			writeError(w, 409, "идёт применение конфигурации")
			return
		}
		if pending, _ := s.Engine.Pending(); pending {
			writeError(w, 409, "дождитесь подтверждения применения")
			return
		}
		if !sameConfig(d.Base, s.Engine.Current()) {
			writeError(w, 409, "конфигурация изменена другим пользователем; отмените свой черновик и повторите изменения")
			return
		}
		if r.Method == http.MethodPut {
			v, ok := draftPrecondition(w, r)
			if !ok {
				return
			}
			if v != d.Version {
				writeError(w, 409, "черновик уже изменён; обновите страницу")
				return
			}
		}
		var incoming config.Config
		if err := readJSON(r, &incoming); err != nil {
			writeError(w, 400, "некорректная конфигурация")
			return
		}
		next, err := mergeScopedConfig(r, cfg, &incoming)
		if err != nil {
			writeError(w, 403, "%v", err)
			return
		}
		result := next.Validate()
		if p == "/api/config/validate" {
			writeJSON(w, 200, result)
			return
		}
		if result.HasErrors() {
			writeJSON(w, 422, errorResponse{Error: "конфигурация содержит ошибки", Problems: result.Problems})
			return
		}
		d.Config = next
		if sameConfig(next, d.Base) {
			d.Config = nil
		}
		d.Version++
		cfg = next
	}
	if p == "/api/config/discard" {
		if s.draftApplying {
			writeError(w, 409, "идёт применение конфигурации")
			return
		}
		v, ok := draftPrecondition(w, r)
		if !ok {
			return
		}
		if v != d.Version {
			writeError(w, 409, "черновик уже изменён")
			return
		}
		d.Config = nil
		d.Base = s.Engine.Current()
		d.Version++
		writeJSON(w, 200, map[string]any{"ok": true, "draft_version": d.Version})
		return
	}
	if p == "/api/config/plan" {
		if !sameConfig(d.Base, s.Engine.Current()) {
			writeError(w, 409, "применённая конфигурация изменилась; пересоздайте черновик")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		actions, err := s.Engine.PlanContext(ctx, cfg)
		if err != nil {
			writeError(w, 500, "не удалось построить план")
			return
		}
		writeJSON(w, 200, map[string]any{"actions": actions})
		return
	}
	visible, err := scopedConfig(r, cfg)
	if err != nil {
		writeError(w, 500, "не удалось подготовить настройки")
		return
	}
	pending, deadline := s.Engine.Pending()
	resp := configResponse{Config: visible, Dirty: d.Config != nil, DraftVersion: d.Version, Pending: pending && (roleOf(r) == "admin" || s.pendingOwner == userOf(r)), Problems: []config.Problem{}}
	if roleOf(r) == "admin" {
		resp.Problems = cfg.Validate().Problems
		resp.Rollback = s.Engine.LastRollback()
	}
	if resp.Pending {
		resp.Deadline = &deadline
	}
	writeJSON(w, 200, resp)
}

func (s *Server) ownsPending(r *http.Request) bool {
	if roleOf(r) == "admin" {
		return true
	}
	s.draftMu.RLock()
	defer s.draftMu.RUnlock()
	return s.pendingOwner != "" && s.pendingOwner == userOf(r)
}
