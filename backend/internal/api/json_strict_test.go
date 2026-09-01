package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestConfigJSONRejectsUnknownFieldsAtEveryDepth(t *testing.T) {
	for _, body := range []string{
		`{"version":1,"unknown_setting":true}`,
		`{"version":1,"system":{"hostname":"netos","unknown_setting":true}}`,
		`{"version":1,"multiwan":{"enabled":true,"mode":"balance","sticky_connection":false}}`,
	} {
		t.Run(body, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/config", strings.NewReader(body))
			var cfg config.Config
			if err := readJSON(req, &cfg); err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("unknown field accepted: err=%v cfg=%+v", err, cfg)
			}
		})
	}
}

func TestConfigHandlersDoNotNormalizeCurrentErrorsAway(t *testing.T) {
	cfg := config.Default()
	cfg.System.Panel.Port = 0
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	server := &Server{}
	validateReq := httptest.NewRequest(http.MethodPost, "/api/config/validate", strings.NewReader(string(body)))
	validateRec := httptest.NewRecorder()
	server.handleValidate(validateRec, validateReq)
	if validateRec.Code != http.StatusOK {
		t.Fatalf("validate status=%d body=%s", validateRec.Code, validateRec.Body.String())
	}
	var result config.ValidationResult
	if err := json.Unmarshal(validateRec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, problem := range result.Problems {
		if problem.Path == "system.panel.port" && problem.Severity == "error" {
			found = true
		}
	}
	if !found {
		t.Fatalf("current zero panel port disappeared before validation: %+v", result.Problems)
	}

	saveReq := httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(string(body)))
	saveRec := httptest.NewRecorder()
	server.handleSaveConfig(saveRec, saveReq)
	if saveRec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("save status=%d body=%s", saveRec.Code, saveRec.Body.String())
	}
}

func TestConfigHandlerMigratesPreviousSchemaBeforeValidation(t *testing.T) {
	cfg := config.Default()
	cfg.Version = config.Version - 1
	cfg.System.Panel.Port = 0
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/config/validate", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	(&Server{}).handleValidate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var result config.ValidationResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	for _, problem := range result.Problems {
		if problem.Path == "version" || problem.Path == "system.panel.port" {
			t.Fatalf("previous schema was not migrated: %+v", result.Problems)
		}
	}
}
