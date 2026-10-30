package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/components"
)

func (s *Server) StartComponentUpdates(ctx context.Context, component *components.Subsystem, path string) {
	s.componentContext = ctx
	s.ComponentUpdates = components.NewUpdateManager(component, path)
	s.ComponentUpdates.Run = func(ctx context.Context, fn func() error) error {
		if !s.configOpMu.TryLock() {
			return fmt.Errorf("идёт изменение конфигурации; повторите позже")
		}
		defer s.configOpMu.Unlock()
		s.draftMu.Lock()
		if s.Maintenance != nil {
			state := s.Maintenance.Status(ctx)
			if state["state"] == "activating" || state["state"] == "active" {
				s.draftMu.Unlock()
				return fmt.Errorf("запланировано обслуживание; дождитесь его окончания")
			}
		}
		if s.draftApplying {
			s.draftMu.Unlock()
			return fmt.Errorf("идёт применение конфигурации")
		}
		if pending, _ := s.Engine.Pending(); pending {
			s.draftMu.Unlock()
			return fmt.Errorf("сначала подтвердите или откатите применение")
		}
		s.draftApplying = true
		s.draftMu.Unlock()
		defer func() { s.draftMu.Lock(); s.draftApplying = false; s.draftMu.Unlock() }()
		return s.Engine.Maintain(ctx, func(_ *config.Config) error { return fn() })
	}
	go s.ComponentUpdates.Serve(ctx)
}
func (s *Server) handleComponentUpdates(w http.ResponseWriter, r *http.Request) {
	if s.ComponentUpdates == nil {
		writeError(w, 503, "обновления компонентов недоступны")
		return
	}
	writeJSON(w, 200, s.ComponentUpdates.Snapshot())
}
func (s *Server) handleComponentCheck(w http.ResponseWriter, r *http.Request) {
	s.startComponentOperation(w, r, "", "")
}
func (s *Server) handleComponentUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, 400, "некорректный запрос")
		return
	}
	id := r.PathValue("id")
	known := false
	for _, c := range config.Catalog {
		if c.ID == id {
			known = true
			break
		}
	}
	if !known || req.Token == "" {
		writeError(w, 400, "неизвестный компонент или версия")
		return
	}
	s.startComponentOperation(w, r, id, req.Token)
}
func (s *Server) startComponentOperation(w http.ResponseWriter, r *http.Request, id, token string) {
	if !may(r, "components", true) {
		writeError(w, 403, "недостаточно прав")
		return
	}
	if s.ComponentUpdates == nil {
		writeError(w, 503, "обновления компонентов недоступны")
		return
	}
	if err := s.ComponentUpdates.Start(s.componentContext, id, token); err != nil {
		writeError(w, 409, "%s", err)
		return
	}
	writeJSON(w, 202, map[string]bool{"started": true})
}
