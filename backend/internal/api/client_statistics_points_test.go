package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	netosruntime "github.com/netos-router/netos/internal/runtime"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestClientStatisticsPointsOptOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.db")
	h, err := netosruntime.NewClientHistory(path, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().Unix() - 10
	if _, err = db.Exec("INSERT INTO traffic VALUES(?,?,?,?,?,?,?)", now, "client", "Client", "192.0.2.1", 100, 200, 30); err != nil {
		t.Fatal(err)
	}
	s := &Server{ClientHistory: h}
	var full netosruntime.ClientReport
	for _, q := range []string{"", "&points=1", "&points=0"} {
		w := httptest.NewRecorder()
		s.handleClientStatistics(w, httptest.NewRequest("GET", fmt.Sprintf("/api/statistics/clients?from=%d&to=%d%s", now-60, now+1, q), nil))
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var report netosruntime.ClientReport
		if err = json.Unmarshal(w.Body.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if q == "" {
			full = report
			if len(full.Points) != 1 {
				t.Fatal("default points missing")
			}
			continue
		}
		want := full
		if q == "&points=0" {
			want.Points = []netosruntime.ClientPoint{}
		}
		if !reflect.DeepEqual(want, report) {
			t.Fatalf("%s differs: %+v %+v", q, want, report)
		}
	}
}
