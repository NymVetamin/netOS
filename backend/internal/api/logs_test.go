package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/eventlog"
)

func logRequest(s *Server, query string, admin bool, ctx context.Context) (int, eventlog.Page) {
	req := httptest.NewRequest("GET", "/api/logs?"+query, nil)
	if admin {
		ctx = context.WithValue(ctx, ctxRole, "admin")
	}
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	s.handleLogs(w, req)
	var p eventlog.Page
	_ = json.Unmarshal(w.Body.Bytes(), &p)
	return w.Code, p
}

func TestLogsAuthorizationAndTopics(t *testing.T) {
	s := &Server{Events: eventlog.New()}
	s.Events.Add(time.Now(), eventlog.Services, eventlog.Info, "netos-dnsmasq", "запущена")
	if code, _ := logRequest(s, "topic=all", false, context.Background()); code != 403 {
		t.Fatal("unauthorized log read", code)
	}
	if code, _ := logRequest(s, "topic=/etc/passwd", true, context.Background()); code != 400 {
		t.Fatal("unknown topic", code)
	}
	if code, _ := logRequest(s, "after=x", true, context.Background()); code != 400 {
		t.Fatal("bad sequence", code)
	}
	code, p := logRequest(s, "", true, context.Background())
	if code != 200 || !p.Reset || len(p.Events) != 1 || p.Events[0].Topic != eventlog.Services {
		t.Fatal(code, p)
	}
}

func TestLogsLongPollWakesOnlyForItsTopic(t *testing.T) {
	s := &Server{Events: eventlog.New()}
	s.Events.Add(time.Now(), eventlog.Access, eventlog.Info, "SSH", "вход")
	_, first := logRequest(s, "topic=access", true, context.Background())
	done := make(chan eventlog.Page, 1)
	go func() {
		_, p := logRequest(s, fmt.Sprintf("topic=access&epoch=%s&after=%d", first.Epoch, first.Latest), true, context.Background())
		done <- p
	}()
	time.Sleep(50 * time.Millisecond)
	s.Events.Add(time.Now(), eventlog.Firewall, eventlog.Info, "r", "other topic")
	select {
	case p := <-done:
		t.Fatal("woken by another topic", p)
	case <-time.After(100 * time.Millisecond):
	}
	s.Events.Add(time.Now(), eventlog.Access, eventlog.Warning, "SSH", "неудачный вход")
	s.Events.Add(time.Now(), eventlog.Access, eventlog.Warning, "SSH", "неудачный вход 2")
	select {
	case p := <-done:
		// The burst arrives as one batch, newest first, without a reset.
		if p.Reset || len(p.Events) != 2 || p.Events[0].Message != "неудачный вход 2" {
			t.Fatal(p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("long poll not woken")
	}
}

func TestLogsLongPollStopsWithClient(t *testing.T) {
	s := &Server{Events: eventlog.New()}
	_, first := logRequest(s, "", true, context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		logRequest(s, fmt.Sprintf("epoch=%s&after=%d", first.Epoch, first.Latest), true, ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("waiter outlived the request")
	}
}

type reasonRunner struct{ args []string }

func (r *reasonRunner) Run(_ context.Context, _ string, args ...string) (string, error) {
	r.args = args
	return "dnsmasq: failed to create listening socket: Address in use\n", nil
}
func (r *reasonRunner) RunInput(context.Context, string, string, ...string) (string, error) {
	return "", fmt.Errorf("unexpected")
}

func TestUnitReasonValidatesInvocation(t *testing.T) {
	r := &reasonRunner{}
	s := &Server{StorageRunner: r}
	if s.unitReason(context.Background(), "x; rm -rf /") != "" || r.args != nil {
		t.Fatal("unvalidated invocation")
	}
	got := s.unitReason(context.Background(), "0123456789abcdef0123456789abcdef")
	if got != "dnsmasq: failed to create listening socket: Address in use" || r.args[len(r.args)-1] != "_SYSTEMD_INVOCATION_ID=0123456789abcdef0123456789abcdef" {
		t.Fatal(got, r.args)
	}
}
