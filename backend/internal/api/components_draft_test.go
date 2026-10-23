package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/store"
)

func TestEveryComponentToggleBackClearsPrivateDraft(t *testing.T) {
	s, _, _, _ := transactionServer(t)
	request := func(method string, cfg *config.Config, version uint64) configResponse {
		t.Helper()
		body, _ := json.Marshal(cfg)
		r := httptest.NewRequest(method, "/api/config", bytes.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), ctxUser, "admin"))
		r = withPanelAccess(r, "admin", store.PanelAccess{Enabled: true})
		r.Header.Set("If-Match", strconv.FormatUint(version, 10))
		w := httptest.NewRecorder()
		if method == "GET" {
			s.handleGetConfig(w, r)
		} else {
			s.handleSaveConfig(w, r)
		}
		if w.Code != 200 {
			t.Fatalf("status=%d %s", w.Code, w.Body.String())
		}
		var got configResponse
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	for _, info := range config.Catalog {
		t.Run(info.ID, func(t *testing.T) {
			got := request("GET", nil, 0)
			got.Config.Components = append(got.Config.Components, config.Component{ID: info.ID, Installed: true})
			got = request("PUT", got.Config, got.DraftVersion)
			if !got.Dirty {
				t.Fatal("installation change lost")
			}
			for i := range got.Config.Components {
				if got.Config.Components[i].ID == info.ID {
					got.Config.Components[i].Installed = false
				}
			}
			got = request("PUT", got.Config, got.DraftVersion)
			if got.Dirty {
				t.Fatal("toggle back left a draft")
			}
			if request("GET", nil, 0).Dirty {
				t.Fatal("draft returned after reload")
			}
		})
	}
	got := request("GET", nil, 0)
	got.Config.System.Hostname = "keep-change"
	got.Config.Components = append(got.Config.Components, config.Component{ID: "xray", Installed: false})
	if !request("PUT", got.Config, got.DraftVersion).Dirty {
		t.Fatal("other change lost")
	}
}
