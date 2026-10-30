package api

import (
	"encoding/json"
	"github.com/netos-router/netos/internal/config"
	"net/http/httptest"
	"testing"
)

func TestClientBaseIdentitiesSurviveReloadAndRespectPermissions(t *testing.T) {
	for _, section := range []string{"clients", "services", "system"} {
		t.Run(section, func(t *testing.T) {
			s, _, _, _ := transactionServer(t)
			base := config.Default()
			base.Clients = []config.Client{{ID: "saved", MAC: "02:00:00:00:00:01"}}
			draft := config.Default()
			draft.Clients = append([]config.Client(nil), base.Clients...)
			draft.Clients = append(draft.Clients, config.Client{ID: "new", MAC: "02:00:00:00:00:02", Blocked: true})
			s.privateDrafts = map[string]*privateDraft{"operator": {Base: base, Config: draft, Version: 7}}
			w := httptest.NewRecorder()
			s.handleGetConfig(w, limitedRequest(map[string]string{section: "view"}))
			if w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			var got configResponse
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if section == "clients" {
				if len(got.BaseClientMACs) != 1 || got.BaseClientMACs[0] != base.Clients[0].MAC {
					t.Fatal("lost base identities or included draft-only client")
				}
			} else if len(got.BaseClientMACs) != 0 {
				t.Fatal("identity metadata leaked")
			}
		})
	}
}
