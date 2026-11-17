package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/eventlog"
	"github.com/netos-router/netos/internal/store"
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

func TestLogsPendingEventsAreBatched(t *testing.T) {
	for _, count := range []int{1, eventlog.Size, eventlog.Size + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			s := &Server{Events: eventlog.New()}
			s.Events.Add(time.Now(), eventlog.Access, eventlog.Info, "SSH", "initial")
			_, p := logRequest(s, "", true, context.Background())
			for repeat := 0; repeat < 2; repeat++ {
				for i := 0; i < count; i++ {
					s.Events.Add(time.Now(), eventlog.Access, eventlog.Info, "SSH", "pending")
				}
				started := time.Now()
				_, p = logRequest(s, fmt.Sprintf("epoch=%s&after=%d", p.Epoch, p.Latest), true, context.Background())
				if elapsed := time.Since(started); elapsed < logBatch {
					t.Fatalf("pending %d events returned after %s, want >=%s", count, elapsed, logBatch)
				}
				t.Logf("%d pending: %s, reset=%v", count, time.Since(started), p.Reset)
				if len(p.Events) != min(count, eventlog.Size) {
					t.Fatalf("lost pending events: got %d want %d", len(p.Events), min(count, eventlog.Size))
				}
			}
		})
	}
}

func TestLogsPendingBatchCanBeCancelled(t *testing.T) {
	s := &Server{Events: eventlog.New()}
	s.Events.Add(time.Now(), eventlog.Access, eventlog.Info, "SSH", "initial")
	_, first := logRequest(s, "", true, context.Background())
	s.Events.Add(time.Now(), eventlog.Access, eventlog.Info, "SSH", "pending")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, p := logRequest(s, fmt.Sprintf("epoch=%s&after=%d", first.Epoch, first.Latest), true, ctx)
	if len(p.Events) != 0 {
		t.Fatal("cancelled request returned a batch")
	}
}

func TestLogsPendingBatchIncludesArrivals(t *testing.T) {
	s := &Server{Events: eventlog.New()}
	s.Events.Add(time.Now(), eventlog.Access, eventlog.Info, "SSH", "initial")
	_, first := logRequest(s, "", true, context.Background())
	s.Events.Add(time.Now(), eventlog.Access, eventlog.Info, "SSH", "pending")
	done := make(chan eventlog.Page, 1)
	go func() {
		_, p := logRequest(s, fmt.Sprintf("epoch=%s&after=%d", first.Epoch, first.Latest), true, context.Background())
		done <- p
	}()
	time.Sleep(logBatch / 4)
	s.Events.Add(time.Now(), eventlog.Access, eventlog.Info, "SSH", "during batch")
	select {
	case p := <-done:
		if len(p.Events) != 2 || p.Events[0].Message != "during batch" {
			t.Fatal(p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("batch did not finish")
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

func TestDNSFileLinesFeedLog(t *testing.T) {
	s := &Server{Events: eventlog.New()}
	s.addDNSLines(time.Now(), []string{
		"Nov 16 10:00:00 dnsmasq[1]: query[A] example.com from 192.168.1.5",
		"Nov 16 10:00:00 dnsmasq[1]: reply example.com is 192.0.2.1",
	})
	p, _, _ := s.Events.Since(eventlog.DNS, "", 0)
	if len(p.Events) != 1 || p.Events[0].Source != "192.168.1.5" || p.Events[0].Message != "example.com (A)" {
		t.Fatal(p.Events)
	}
	if s.queryLog() {
		t.Fatal("query log without configuration")
	}
}

func TestAuditEntriesBecomeEvents(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "netos.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.Audit(store.AuditEntry{User: "admin", Action: "login", SourceIP: "192.0.2.5", Success: true})
	_ = st.Audit(store.AuditEntry{User: "admin", Action: "apply", Target: "7", Detail: "dnsmasq не запустился", Success: false})
	s := &Server{Store: st, Events: eventlog.New()}
	s.refillAudit()
	st.OnAudit = s.addAudit
	_ = st.Audit(store.AuditEntry{User: "admin", Action: "login", SourceIP: "198.51.100.9", Success: false, Detail: "неверные учётные данные"})
	_ = st.Audit(store.AuditEntry{User: "system", Action: "restore", Target: "backup.tar", Success: true})
	_ = st.Audit(store.AuditEntry{User: "system", Action: "rollback", Target: "8", Detail: "timeout: ", Success: true})
	got := func(topic string) []string {
		p, _, _ := s.Events.Since(topic, "", 0)
		out := []string{}
		for i := len(p.Events) - 1; i >= 0; i-- {
			out = append(out, p.Events[i].Level+" "+p.Events[i].Source+": "+p.Events[i].Message)
		}
		return out
	}
	access := strings.Join(got(eventlog.Access), "\n")
	system := strings.Join(got(eventlog.System), "\n")
	if access != "info панель: вход admin с 192.0.2.5\nwarning панель: неудачный вход admin с 198.51.100.9" {
		t.Fatal(access)
	}
	if system != "error admin: применение конфигурации, ревизия 7 — не удалось: dnsmasq не запустился\ninfo system: восстановление из копии: backup.tar\nwarning system: откат конфигурации, ревизия 8 — применение не подтверждено вовремя" {
		t.Fatal(system)
	}
}
