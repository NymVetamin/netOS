package xraylog

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSanitize(t *testing.T) {
	cause := errors.New("invalid UUID SECRET")
	if err := SafeError(cause); !errors.Is(err, cause) || strings.Contains(err.Error(), "SECRET") {
		t.Fatal("diagnostic identity/redaction lost", err)
	}
	for _, input := range []string{
		"from 192.0.2.1:55 rejected proxy/vless/encoding: invalid request user id: SECRET",
		"[Warning] failed > invalid request user id: SECRET",
		"from 192.0.2.1:55 rejected unrecognized auth method SECRET",
		"[Warning] invalid privateKey SECRET",
		"invalid UUID SECRET",
		"password SECRET > invalid request user id: OTHER",
	} {
		if got := Sanitize(input); strings.Contains(got, "SECRET") {
			t.Fatalf("credential survived: %q", got)
		}
	}
	for _, input := range []string{
		"from 192.0.2.1:55 accepted tcp:192.0.2.2:443 [in >> direct] email: srv/peer",
		"from 192.0.2.1:55 rejected proxy/socks: invalid username or password",
		"[Warning] failed to bind port",
		"DNS got answer: password.example -> [192.0.2.1]",
		"DNS got answer: password -> [192.0.2.1]",
		"from 192.0.2.1:55 accepted tcp:uuid.example:443 [in >> direct] email: srv/password",
		"from 192.0.2.1:55 accepted tcp:password:443 [in >> direct] email: srv/uuid",
	} {
		if got := Sanitize(input); got != input {
			t.Fatalf("lost safe details: %q", got)
		}
	}
}

func TestStreamFinalLoss(t *testing.T) {
	var out bytes.Buffer
	w := newStream(&out, func() { t.Error("unexpected cancellation") })
	_, _ = w.Write([]byte(strings.Repeat("safe diagnostic\n", 20)))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "4 messages (oversized=0, resources=0)") {
		t.Fatal(out.String())
	}
}

func TestStreamChunkBoundariesAndOversizedRecovery(t *testing.T) {
	for _, chunk := range []int{1, 31, 65536} {
		var out bytes.Buffer
		w := newStream(&out, func() { t.Error("unexpected cancellation") })
		input := "from 192.0.2.1:55 rejected invalid request user id: SECRET\n" + strings.Repeat("x", 8<<20) + "SECRET\nrecovered\r\nlast"
		for start := 0; start < len(input); start += chunk {
			end := min(start+chunk, len(input))
			if n, err := w.Write([]byte(input[start:end])); n != end-start || err != nil {
				t.Fatal(n, err)
			}
			if cap(w.buf) != maxLine {
				t.Fatalf("buffer grew: %d", cap(w.buf))
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		text := out.String()
		if strings.Contains(text, "SECRET") || !strings.Contains(text, "recovered\nlast\n") || !strings.Contains(text, "1 messages (oversized=1, resources=1)") {
			t.Fatalf("wrong output: %q", text)
		}
		if _, err := w.Write([]byte("late")); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

type lockedBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(p)
}
func (b *lockedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.data.String() }

func TestStreamBudgetsIdleNoticeAndRenewal(t *testing.T) {
	var out lockedBuffer
	w := newStream(&out, func() { t.Error("unexpected cancellation") })
	defer w.Close()
	for i := 0; i < 100; i++ {
		_, _ = w.Write([]byte("from 192.0.2.1:1 accepted tcp:192.0.2.2:2 [in >> direct]\n"))
	}
	for i := 0; i < 20; i++ {
		_, _ = w.Write([]byte("[Warning] bind failed\n"))
	}
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(out.String(), "40 messages") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	text := out.String()
	if strings.Count(text, " accepted ") != 64 || strings.Count(text, "bind failed") != 16 || strings.Count(text, LossPrefix) != 1 || !strings.Contains(text, "40 messages (oversized=0, resources=36)") {
		t.Fatalf("bad budgets: %q", text)
	}
	_, _ = w.Write([]byte("from 192.0.2.1:1 accepted tcp:192.0.2.2:2 [in >> direct]\n"))
	if strings.Count(out.String(), " accepted ") != 65 {
		t.Fatal("window did not renew")
	}
}

type brokenWriter struct{ short bool }

func (b brokenWriter) Write(p []byte) (int, error) {
	if b.short {
		return 0, nil
	}
	return 0, io.ErrClosedPipe
}
func TestStreamOutputFailure(t *testing.T) {
	for _, short := range []bool{false, true} {
		canceled := false
		w := newStream(brokenWriter{short}, func() { canceled = true })
		if _, err := w.Write([]byte("safe\n")); err == nil || !canceled {
			t.Fatal("sink error ignored")
		}
		if err := w.Close(); err == nil {
			t.Fatal("error not retained")
		}
	}
}

func TestRunChild(t *testing.T) {
	if os.Getenv("NETOS_XRAYLOG_TEST_CHILD") != "1" {
		return
	}
	_, _ = io.WriteString(os.Stdout, "from 192.0.2.1:55 rejected invalid request user id: SECRET\n")
	_, _ = io.WriteString(os.Stderr, "[Warning] bind failed\n")
	os.Exit(17)
}

func TestRunCombinedStreamsAndExit(t *testing.T) {
	t.Setenv("NETOS_XRAYLOG_TEST_CHILD", "1")
	var out bytes.Buffer
	err := Run(context.Background(), os.Args[0], []string{"-test.run=^TestRunChild$"}, &out)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 17 {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "SECRET") || !strings.Contains(out.String(), "[скрыто]") || !strings.Contains(out.String(), "bind failed") {
		t.Fatal(out.String())
	}
}

func TestRunMissingExecutable(t *testing.T) {
	if err := Run(context.Background(), t.TempDir()+"/missing", nil, io.Discard); err == nil {
		t.Fatal("missing executable accepted")
	}
}
