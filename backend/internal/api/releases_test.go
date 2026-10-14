package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReleaseListAndErrors(t *testing.T) {
	for _, status := range []int{200, 403, 500} {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			fmt.Fprint(w, `[{"tag_name":"v0.12","body":"Changes","published_at":"2026-10-14T00:00:00Z"},{"tag_name":"v0.13","draft":true},{"tag_name":"v0.14","prerelease":true},{"tag_name":"bad;tag"},{"tag_name":"v0.11","published_at":"2026-10-13T00:00:00Z"}]`)
		}))
		got, err := fetchReleases(context.Background(), ts.Client(), ts.URL)
		ts.Close()
		if status != 200 {
			if err == nil {
				t.Fatal("HTTP error accepted")
			}
			continue
		}
		if err != nil || len(got) != 2 || got[0].Tag != "v0.12" || got[0].Body != "Changes" {
			t.Fatalf("%+v %v", got, err)
		}
	}
}
func TestReleaseListLimit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "[")
		for i := 1; i <= 15; i++ {
			if i > 1 {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, `{"tag_name":"v0.%d","published_at":"2026-10-%02dT00:00:00Z"}`, i, i)
		}
		fmt.Fprint(w, "]")
	}))
	defer ts.Close()
	got, err := fetchReleases(context.Background(), ts.Client(), ts.URL)
	if err != nil || len(got) != 10 || got[0].Tag != "v0.15" || got[9].Tag != "v0.6" {
		t.Fatalf("%+v %v", got, err)
	}
}
func TestUpdateBackupSchedule(t *testing.T) {
	for _, backup := range []bool{false, true} {
		runner := &maintenanceRunner{}
		m := &Maintenance{Runner: runner, Binary: "netos", Unit: "test"}
		if err := m.Schedule(context.Background(), "update", "v0.12", backup); err != nil {
			t.Fatal(err)
		}
		cmd := runner.commands[len(runner.commands)-1]
		if strings.Contains(cmd, "--backup") != backup {
			t.Fatal(cmd)
		}
	}
}

func TestUpdateAPIRejectsDowngrade(t *testing.T) {
	s, cookie, csrf := newAuthedServer(t)
	s.Version = "v0.12"
	runner := &maintenanceRunner{}
	s.Maintenance = &Maintenance{Runner: runner, Binary: "netos", Unit: "test"}
	w := serveAuthed(s.Routes(), http.MethodPost, "/api/maintenance/update", []byte(`{"version":"v0.11","confirm":"UPDATE"}`), cookie, csrf)
	if w.Code != http.StatusConflict || len(runner.commands) != 0 {
		t.Fatalf("status=%d commands=%v", w.Code, runner.commands)
	}
}
