// Package xraylog bounds and sanitizes Xray output before it reaches journald.
package xraylog

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

const maxLine = 8192
const LossPrefix = "netos-xray-log-v1 Suppressed "

var credentialLabel = regexp.MustCompile(`(?i)\b(?:password|passwd|uuid|private.?key|preshared.?key|preSharedKey)(?:\s+|[:=])`)
var acceptedRecord = regexp.MustCompile(`^(?:[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9:.]+ )?from (?:tcp:|udp:)?(?:\[[0-9a-fA-F:.]+\]|[0-9.]+):[0-9]+ accepted (?:tcp|udp):\S+ \[[^\[\]\r\n]+\](?: email: \S+)?$`)
var rejectedHeader = regexp.MustCompile(`^(?:[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9:.]+ )?from (?:tcp:|udp:)?(?:\[[0-9a-fA-F:.]+\]|[0-9.]+):[0-9]+ rejected `)
var dnsRecord = regexp.MustCompile(`(?:got answer:|cache HIT:|cache OPTIMISTE:)\s+\S+\s+->\s+\[[0-9a-fA-F:.,\s]*\]\s*$`)

type sanitizedError struct{ cause error }

func (e sanitizedError) Error() string { return Sanitize(e.cause.Error()) }
func (e sanitizedError) Unwrap() error { return e.cause }

// SafeError preserves error identity while keeping diagnostic text safe to log.
func SafeError(err error) error {
	if err == nil {
		return nil
	}
	return sanitizedError{err}
}

// Sanitize also protects diagnostics, which may repeat an authentication error.
// Unknown rejection formats cannot be trusted to omit credentials.
func Sanitize(s string) string {
	// These fields are public connection/resource metadata, not diagnostics.
	// A host named "password" must not disappear from traffic history.
	if acceptedRecord.MatchString(s) {
		return s
	}
	if header := rejectedHeader.FindString(s); header != "" {
		reason := strings.TrimSpace(s[len(header):])
		if reason == "proxy/socks: invalid username or password" {
			return s
		}
		for _, prefix := range []string{"proxy/vless/encoding: invalid request user id:", "invalid request user id:"} {
			if strings.HasPrefix(reason, prefix) {
				return header + prefix + " [скрыто]"
			}
		}
		return header + "[подробности отказа скрыты: формат может содержать учётные данные]"
	}
	if match := dnsRecord.FindString(s); match != "" {
		// Upstream descriptions are not needed for the process-scoped DNS join.
		return "DNS " + match
	}
	// The known SOCKS diagnostic names the credential field but prints no value.
	if credentialLabel.MatchString(strings.ReplaceAll(s, "proxy/socks: invalid username or password", "")) {
		return "[Warning] Xray: подробности диагностики скрыты: возможны учётные данные"
	}
	if i := strings.Index(s, "invalid request user id:"); i >= 0 {
		return s[:i] + "invalid request user id: [скрыто]"
	}
	if i := strings.Index(s, " rejected "); i >= 0 {
		reason := strings.TrimSpace(s[i+10:])
		if reason == "proxy/socks: invalid username or password" {
			return s
		}
		return s[:i] + " rejected [подробности отказа скрыты: формат может содержать учётные данные]"
	}
	return s
}

// stream has constant memory independent of line size, connection count and
// runtime. The only timer exists while a loss notice is pending; idle streams
// do not wake up. Both exec output streams use this same comparable writer.
type stream struct {
	mu           sync.Mutex
	out          io.Writer
	cancel       func()
	buf          []byte
	oversized    bool
	window       time.Time
	used         [2]int
	lost, long   uint64
	resourceLoss uint64
	timer        *time.Timer
	err          error
	closed       bool
}

func newStream(out io.Writer, cancel func()) *stream {
	return &stream{out: out, cancel: cancel, buf: make([]byte, 0, maxLine)}
}

func (s *stream) emit(text string) {
	if s.err != nil {
		return
	}
	n, err := io.WriteString(s.out, text+"\n")
	if err == nil && n != len(text)+1 {
		err = io.ErrShortWrite
	}
	if err != nil {
		s.err = err
		s.cancel()
	}
}

func (s *stream) reportLoss() {
	if s.lost == 0 {
		return
	}
	s.emit(fmt.Sprintf("%s%d messages (oversized=%d, resources=%d)", LossPrefix, s.lost, s.long, s.resourceLoss))
	s.lost, s.long, s.resourceLoss = 0, 0, 0
}

func (s *stream) drop(oversized, resource bool) {
	s.lost++
	if resource {
		s.resourceLoss++
	}
	if oversized {
		s.long++
	}
	if s.timer == nil && !s.closed {
		s.timer = time.AfterFunc(time.Second, func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.timer = nil
			if !s.closed {
				s.reportLoss()
			}
		})
	}
}

func (s *stream) line() {
	if s.oversized {
		s.drop(true, true)
		s.oversized = false
		s.buf = s.buf[:0]
		return
	}
	text := strings.TrimSuffix(string(s.buf), "\r")
	s.buf = s.buf[:0]
	if text == "" {
		return
	}
	now := time.Now()
	if s.window.IsZero() || now.Sub(s.window) >= time.Second {
		s.reportLoss()
		s.window, s.used = now, [2]int{}
	}
	class, limit := 1, 16
	if strings.Contains(text, " accepted ") || strings.Contains(text, " rejected ") ||
		strings.Contains(text, "got answer:") || strings.Contains(text, "cache HIT:") || strings.Contains(text, "cache OPTIMISTE:") {
		class, limit = 0, 64
	}
	if s.used[class] >= limit {
		s.drop(false, class == 0)
		return
	}
	s.used[class]++
	s.emit(Sanitize(text))
}

func (s *stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	if s.err != nil {
		return 0, s.err
	}
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		part := p
		if i >= 0 {
			part = p[:i]
		}
		if !s.oversized {
			if len(s.buf)+len(part) > maxLine {
				s.oversized = true
				s.buf = s.buf[:0]
			} else {
				s.buf = append(s.buf, part...)
			}
		}
		if i < 0 {
			break
		}
		s.line()
		if s.err != nil {
			return n - len(p), s.err
		}
		p = p[i+1:]
	}
	return n, nil
}

func (s *stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		if s.timer != nil {
			s.timer.Stop()
		}
		if len(s.buf) > 0 || s.oversized {
			s.line()
		}
		s.reportLoss()
	}
	return s.err
}
