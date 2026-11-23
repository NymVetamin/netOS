package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
)

type pausedDraftBody struct {
	io.Reader
	entered, release chan struct{}
	once             sync.Once
}

func BenchmarkPrivateDraftIO(b *testing.B) {
	for _, padding := range []int{0, 256 << 10} {
		b.Run(fmt.Sprint(padding), func(b *testing.B) {
			s := &Server{Engine: apply.NewEngine(nil, true)}
			cfg := config.Default()
			if _, err := s.Engine.Apply(context.Background(), cfg, 0, false); err != nil {
				b.Fatal(err)
			}
			data, err := json.Marshal(cfg)
			if err != nil {
				b.Fatal(err)
			}
			body := strings.Repeat(" ", padding) + string(data)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				w := httptest.NewRecorder()
				s.handlePrivateConfig(w, privateIORequest(http.MethodPost, "/api/config/validate", "alice", strings.NewReader(body)))
				if w.Code != http.StatusOK {
					b.Fatal(w.Code, w.Body.String())
				}
			}
		})
	}
}

func (b *pausedDraftBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered); <-b.release })
	return b.Reader.Read(p)
}
func (b *pausedDraftBody) Close() error { return nil }

func privateIORequest(method, path, user string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, path, body)
	r.Header.Set("If-Match", "1")
	return r.WithContext(context.WithValue(context.WithValue(r.Context(), ctxUser, user), ctxRole, "admin"))
}

func TestPrivateDraftSlowBodyDoesNotBlockOtherUsers(t *testing.T) {
	for _, padding := range []int{0, 256 << 10} {
		s, _, _, _ := transactionServer(t)
		cfg := *s.Engine.Current()
		cfg.System.Hostname = "pending-host"
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		body := &pausedDraftBody{Reader: strings.NewReader(strings.Repeat(" ", padding) + string(data)), entered: make(chan struct{}), release: make(chan struct{})}
		r := privateIORequest(http.MethodPut, "/api/config", "alice", nil)
		r.Body = body
		w := httptest.NewRecorder()
		done := make(chan struct{})
		go func() { defer close(done); s.handlePrivateConfig(w, r) }()
		select {
		case <-body.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("body not reached")
		}
		read := make(chan struct{})
		go func() { s.requestConfig(privateIORequest(http.MethodGet, "/api/config", "bob", nil)); close(read) }()
		blocked := false
		select {
		case <-read:
		case <-time.After(time.Second):
			blocked = true
		}
		close(body.release)
		<-done
		<-read
		if blocked {
			t.Errorf("body padding=%d: Bob blocked on Alice's network read", padding)
		}
		if w.Code != 200 {
			t.Fatalf("save: %d %s", w.Code, w.Body.String())
		}
	}
}

type pausedDraftWriter struct {
	*httptest.ResponseRecorder
	entered, release chan struct{}
}

func (w *pausedDraftWriter) WriteHeader(code int) {
	close(w.entered)
	<-w.release
	w.ResponseRecorder.WriteHeader(code)
}

func TestPrivateDraftSlowResponseDoesNotBlockOtherUsers(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/api/config", 200},
		{http.MethodPut, "/api/config", 400},
		{http.MethodPost, "/api/config/discard", 200},
		{http.MethodPost, "/api/config/validate", 400},
		{http.MethodGet, "/api/config/plan", 200},
	} {
		t.Run(tc.path+tc.method, func(t *testing.T) {
			s, _, _, _ := transactionServer(t)
			w := &pausedDraftWriter{httptest.NewRecorder(), make(chan struct{}), make(chan struct{})}
			done := make(chan struct{})
			go func() {
				defer close(done)
				s.handlePrivateConfig(w, privateIORequest(tc.method, tc.path, "alice", nil))
			}()
			select {
			case <-w.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("response not reached")
			}
			read := make(chan struct{})
			go func() { s.requestConfig(privateIORequest(http.MethodGet, "/api/config", "bob", nil)); close(read) }()
			blocked := false
			select {
			case <-read:
			case <-time.After(time.Second):
				blocked = true
			}
			close(w.release)
			<-done
			<-read
			if blocked {
				t.Error("Bob blocked on Alice's response writer")
			}
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestPrivateDraftUploadRechecksConcurrentChanges(t *testing.T) {
	for _, change := range []string{"edit", "discard", "applying", "active", "pending", "replaced"} {
		t.Run(change, func(t *testing.T) {
			s, cookie, csrf, _ := transactionServer(t)
			cfg := *s.Engine.Current()
			cfg.System.Hostname = "late-upload"
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			body := &pausedDraftBody{Reader: strings.NewReader(string(data)), entered: make(chan struct{}), release: make(chan struct{})}
			r := privateIORequest(http.MethodPut, "/api/config", "alice", nil)
			r.Body = body
			w := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { defer close(done); s.handlePrivateConfig(w, r) }()
			var releaseOnce sync.Once
			finish := func() { releaseOnce.Do(func() { close(body.release) }); <-done }
			defer finish()
			select {
			case <-body.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("body not reached")
			}
			switch change {
			case "edit", "discard":
				other := httptest.NewRecorder()
				req := privateIORequest(http.MethodPost, "/api/config/discard", "alice", nil)
				if change == "edit" {
					cfg.System.Hostname = "winning-edit"
					data, _ = json.Marshal(cfg)
					req = privateIORequest(http.MethodPut, "/api/config", "alice", strings.NewReader(string(data)))
				}
				s.handlePrivateConfig(other, req)
				if other.Code != 200 {
					t.Fatalf("concurrent operation: %d %s", other.Code, other.Body.String())
				}
			case "applying":
				s.draftMu.Lock()
				s.draftApplying = true
				s.draftMu.Unlock()
			case "active":
				cfg.System.Hostname = "new-active"
				if _, err := s.Engine.Apply(context.Background(), &cfg, 0, false); err != nil {
					t.Fatal(err)
				}
			case "pending":
				applyDraft(t, s, cookie, csrf, "pending-apply")
				t.Cleanup(func() {
					if _, err := s.Engine.Confirm(s.Store.MarkActive); err != nil {
						t.Error(err)
					}
				})
			case "replaced":
				s.draftMu.Lock()
				delete(s.privateDrafts, "alice")
				s.draftMu.Unlock()
			}
			finish()
			if w.Code != http.StatusConflict {
				t.Fatalf("late request: %d %s", w.Code, w.Body.String())
			}
			if got := s.requestConfig(privateIORequest(http.MethodGet, "/api/config", "alice", nil)); got.System.Hostname == "late-upload" {
				t.Fatal("late upload overwrote current draft")
			}
		})
	}
}
