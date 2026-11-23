package api

import (
	"context"
	"net/http"
	"time"

	"github.com/netos-router/netos/internal/apply"
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
	status, response := s.privateConfigResponse(r)
	// No network writes may hold the lock shared by all private drafts.
	writeJSON(w, status, response)
}

func (s *Server) privateConfigResponse(r *http.Request) (int, any) {
	if s.Engine == nil {
		return 503, errorResponse{Error: "конфигурация недоступна"}
	}
	s.draftMu.Lock()
	defer s.draftMu.Unlock()
	d := s.privateDraftLocked(userOf(r))
	cfg := d.Config
	if cfg == nil {
		cfg = d.Base
	}
	if cfg == nil {
		return 503, errorResponse{Error: "конфигурация ещё не загружена"}
	}
	p := r.URL.Path
	var validation *config.ValidationResult
	if r.Method == http.MethodPut || p == "/api/config/validate" {
		if s.draftApplying {
			return 409, errorResponse{Error: "идёт применение конфигурации"}
		}
		if pending, _ := s.Engine.Pending(); pending {
			return 409, errorResponse{Error: "дождитесь подтверждения применения"}
		}
		if !sameConfig(d.Base, s.Engine.Current()) {
			return 409, errorResponse{Error: "конфигурация изменена другим пользователем; отмените свой черновик и повторите изменения"}
		}
		if r.Method == http.MethodPut {
			v, status, message := parseDraftPrecondition(r)
			if status != 0 {
				return status, errorResponse{Error: message}
			}
			if v != d.Version {
				return 409, errorResponse{Error: "черновик уже изменён; обновите страницу"}
			}
		}
		version, base := d.Version, s.Engine.Current()
		var incoming config.Config
		// A client can stall while uploading. Revalidate the snapshot after
		// reading without the global draft lock, just as the planner does.
		s.draftMu.Unlock()
		readErr := func() error {
			defer s.draftMu.Lock()
			return readJSON(r, &incoming)
		}()
		if readErr != nil {
			return 400, errorResponse{Error: "некорректная конфигурация"}
		}
		pending, _ := s.Engine.Pending()
		if s.draftApplying || pending || s.privateDrafts[userOf(r)] != d || d.Version != version || s.Engine.Current() != base {
			return 409, errorResponse{Error: "черновик или применённая конфигурация изменились; обновите страницу и повторите изменения"}
		}
		next, err := mergeScopedConfig(r, cfg, &incoming)
		if err != nil {
			return 403, errorResponse{Error: err.Error()}
		}
		result := next.Validate()
		validation = result
		if p == "/api/config/validate" {
			return 200, result
		}
		if result.HasErrors() {
			return 422, errorResponse{Error: "конфигурация содержит ошибки", Problems: result.Problems}
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
			return 409, errorResponse{Error: "идёт применение конфигурации"}
		}
		v, status, message := parseDraftPrecondition(r)
		if status != 0 {
			return status, errorResponse{Error: message}
		}
		if v != d.Version {
			return 409, errorResponse{Error: "черновик уже изменён"}
		}
		d.Config = nil
		d.Base = s.Engine.Current()
		d.Version++
		return 200, map[string]any{"ok": true, "draft_version": d.Version}
	}
	if p == "/api/config/plan" {
		if s.draftApplying {
			return 409, errorResponse{Error: "идёт применение конфигурации: дождитесь его окончания"}
		}
		if pending, _ := s.Engine.Pending(); pending {
			return 409, errorResponse{Error: "дождитесь подтверждения или отката текущего применения"}
		}
		if !sameConfig(d.Base, s.Engine.Current()) {
			return 409, errorResponse{Error: "применённая конфигурация изменилась; пересоздайте черновик"}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		old := s.Engine.Current()
		version := d.Version
		// Draft edits replace Config rather than mutating the published snapshot.
		// Slow OS reads in preview must not hold up unrelated draft operations.
		s.draftMu.Unlock()
		actions, err := func() ([]apply.Action, error) {
			defer s.draftMu.Lock()
			return s.Engine.PlanFromContext(managementContext(ctx, r), old, cfg)
		}()
		pending, _ := s.Engine.Pending()
		if s.draftApplying || pending || s.privateDrafts[userOf(r)] != d || d.Version != version || s.Engine.Current() != old {
			return 409, errorResponse{Error: "черновик или применённая конфигурация изменились; обновите страницу и проверьте изменения"}
		}
		if err != nil {
			return 500, errorResponse{Error: "не удалось построить план"}
		}
		response, err := describePlan(r, old, cfg, actions, d.Version)
		if err != nil {
			return 500, errorResponse{Error: "не удалось описать изменения"}
		}
		return 200, response
	}
	visible, err := scopedConfig(r, cfg)
	if err != nil {
		return 500, errorResponse{Error: "не удалось подготовить настройки"}
	}
	revision, deadline := s.Engine.PendingRevision()
	resp := configResponse{Config: visible, Dirty: d.Config != nil, DraftVersion: d.Version, Pending: !deadline.IsZero() && (roleOf(r) == "admin" || s.pendingOwner == userOf(r)), Problems: []config.Problem{}}
	if anySection(r, false, "clients") {
		for _, client := range d.Base.Clients {
			resp.BaseClientMACs = append(resp.BaseClientMACs, client.MAC)
		}
	}
	if anySection(r, false, "clients", "services") {
		resp.BaseReservations = d.Base.DHCP.Reservations
	}
	if roleOf(r) == "admin" {
		if validation == nil {
			validation = cfg.Validate()
		}
		resp.Problems = validation.Problems
		resp.Rollback = s.Engine.LastRollback()
	}
	if resp.Pending {
		resp.PendingRevision = revision
		resp.Deadline = &deadline
	}
	return 200, resp
}

func (s *Server) ownsPending(r *http.Request) bool {
	if roleOf(r) == "admin" {
		return true
	}
	s.draftMu.RLock()
	defer s.draftMu.RUnlock()
	return s.pendingOwner != "" && s.pendingOwner == userOf(r)
}
