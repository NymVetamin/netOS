package api

import (
	"context"
	"net/http"
	"sort"
	"strings"
)

// Only serve this handler on the root-only Unix socket, never on the panel.
func (s *Server) localControlHandler() http.Handler {
	mux := http.NewServeMux()
	root := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), ctxUser, "root")
			ctx = context.WithValue(ctx, ctxRole, "admin")
			h(w, r.WithContext(ctx))
		}
	}
	draft := func(w http.ResponseWriter, r *http.Request) {
		owner := r.URL.Query().Get("user")
		s.draftMu.Lock()
		owners := []string{}
		for name, d := range s.privateDrafts {
			if d != nil && d.Config != nil {
				owners = append(owners, name)
			}
		}
		if owner == "" && len(owners) > 1 {
			s.draftMu.Unlock()
			sort.Strings(owners)
			writeError(w, 409, "несколько черновиков (%s); укажите netos apply --user <логин>", strings.Join(owners, ", "))
			return
		}
		if owner == "" && len(owners) == 1 {
			owner = owners[0]
		}
		d := s.privateDrafts[owner]
		if d == nil || d.Config == nil {
			s.draftMu.Unlock()
			if owner != "" || r.Method == http.MethodPost {
				writeError(w, 409, "нет изменений в выбранном черновике")
			} else {
				writeJSON(w, 200, map[string]any{"dirty": false})
			}
			return
		}
		version := d.Version
		s.draftMu.Unlock()
		if r.Method == http.MethodGet {
			writeJSON(w, 200, map[string]any{"owner": owner, "dirty": true, "draft_version": version})
			return
		}
		// Keep the selected owner fixed. handleApply rechecks the version and
		// baseline under draftMu, even if another user edits in the meantime.
		s.handleApply(w, r.WithContext(context.WithValue(r.Context(), ctxUser, owner)))
	}
	mux.HandleFunc("GET /draft", root(draft))
	mux.HandleFunc("POST /apply", root(draft))
	mux.HandleFunc("POST /confirm", root(s.handleConfirm))
	mux.HandleFunc("GET /status", root(s.handleStatus))
	return mux
}
