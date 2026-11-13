package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/netos-router/netos/internal/store"
	"math/rand"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type accessPageRunner struct {
	accessLogRunner
	rows  []string
	calls int
}

func (r *accessPageRunner) Run(_ context.Context, _ string, args ...string) (string, error) {
	r.calls++
	if r.fail {
		return "", fmt.Errorf("fixture unavailable")
	}
	start, limit := 0, 0
	for i, a := range args {
		if strings.HasPrefix(a, "--grep") {
			return "", fmt.Errorf("unbounded grep")
		}
		if a == "-n" {
			if args[i+1] == "+1" {
				if len(r.rows) == 0 {
					return "", nil
				}
				return r.rows[len(r.rows)-1], nil
			}
			limit, _ = strconv.Atoi(args[i+1])
		}
		if strings.HasPrefix(a, "--cursor=") {
			anchor := strings.TrimPrefix(a, "--cursor=")
			start = len(r.rows)
			for j, raw := range r.rows {
				var row map[string]string
				_ = json.Unmarshal([]byte(raw), &row)
				if row["__CURSOR"] == anchor {
					start = j
					break
				}
			}
		}
	}
	if limit < 1 || limit > 502 {
		return "", fmt.Errorf("invalid limit %d", limit)
	}
	return strings.Join(r.rows[start:min(start+limit, len(r.rows))], "\n"), nil
}
func accessPageRow(id, message string) string {
	data, _ := json.Marshal(map[string]string{"__CURSOR": id, "__REALTIME_TIMESTAMP": vpnPageFixtureTime, "_SYSTEMD_UNIT": "ssh.service", "MESSAGE": message})
	return string(data)
}
func requestAccessPage(t *testing.T, s *Server, query string) (journalLogPage, int) {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/logs?kind=access&"+query, nil)
	r = r.WithContext(context.WithValue(r.Context(), ctxRole, "admin"))
	w := httptest.NewRecorder()
	s.handleLogs(w, r)
	var p journalLogPage
	if w.Code == 200 {
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
	}
	return p, w.Code
}
func TestAccessPagesSnapshotMergeAndNoise(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for i := 0; i < 350; i++ {
		if err := st.Audit(store.AuditEntry{Action: "login", User: "alice", Success: true}); err != nil {
			t.Fatal(err)
		}
	}
	run := &accessPageRunner{}
	for i := 0; i < 901; i++ {
		msg := "noise"
		if i >= 750 {
			msg = "Accepted publickey for alice from 192.0.2.1 port 42 ssh2"
		}
		run.rows = append(run.rows, accessPageRow(fmt.Sprint("j", i), msg))
	}
	s := &Server{Store: st, StorageRunner: run}
	cursor := ""
	seen := map[string]bool{}
	panel, ssh := 0, 0
	pages := 0
	for ; pages < 20; pages++ {
		beforeCalls := run.calls
		p, status := requestAccessPage(t, s, "cursor="+url.QueryEscape(cursor))
		commandLimit := 1
		if pages == 0 {
			commandLimit = 2
		}
		if run.calls-beforeCalls > commandLimit {
			t.Fatal("repeated journal preparation", run.calls-beforeCalls)
		}
		if status != 200 || p.Incomplete || p.Scanned > 500 || len(p.Entries) > 100 {
			t.Fatal(status, p)
		}
		if pages == 0 {
			if len(p.Entries) != 100 {
				t.Fatal(p)
			}
			token, _ := base64.RawURLEncoding.DecodeString(p.Next)
			var c journalLogCursor
			_ = json.Unmarshal(token, &c)
			if c.Anchor != "" || c.Access == nil || c.Access.Upper != "j0" {
				t.Fatal("unconsumed journal snapshot not frozen", c)
			}
			if err := st.Audit(store.AuditEntry{Action: "login", User: "injected", Success: true}); err != nil {
				t.Fatal(err)
			}
			run.rows = append([]string{accessPageRow("injected", "Accepted publickey for injected from 192.0.2.1 port 42 ssh2")}, run.rows...)
		}
		for _, e := range p.Entries {
			if seen[e.ID] || e.User != "alice" {
				t.Fatal("duplicate or new event", e)
			}
			seen[e.ID] = true
			if e.Protocol == "ssh" {
				ssh++
			} else {
				panel++
			}
		}
		cursor = p.Next
		if cursor == "" {
			break
		}
	}
	if panel != 350 || ssh != 151 || cursor != "" {
		t.Fatal(panel, ssh, pages)
	}
}
func TestAccessPagePartialRetryAndPrunedAnchor(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for i := 0; i < 150; i++ {
		if err := st.Audit(store.AuditEntry{Action: "login", User: "alice", Success: true}); err != nil {
			t.Fatal(err)
		}
	}
	run := &accessPageRunner{accessLogRunner: accessLogRunner{fail: true}}
	for i := 0; i < 600; i++ {
		run.rows = append(run.rows, accessPageRow(fmt.Sprint("j", i), "noise"))
	}
	s := &Server{Store: st, StorageRunner: run}
	p, status := requestAccessPage(t, s, "")
	if status != 200 || !p.Incomplete || p.Next != "" || len(p.Entries) != 100 {
		t.Fatal(status, p)
	}
	run.fail = false
	p, status = requestAccessPage(t, s, "")
	if status != 200 || p.Incomplete || p.Next == "" || len(p.Entries) != 100 {
		t.Fatal(status, p)
	}
	next := p.Next
	run.fail = true
	partial, status := requestAccessPage(t, s, "cursor="+url.QueryEscape(next))
	if status != 200 || !partial.Incomplete || partial.Next != "" || len(partial.Entries) != 50 {
		t.Fatal(status, partial)
	}
	run.fail = false
	retry, status := requestAccessPage(t, s, "cursor="+url.QueryEscape(next))
	if status != 200 || retry.Incomplete || !reflect.DeepEqual(retry.Entries, partial.Entries) {
		t.Fatal("retry advanced past preview", status, retry)
	}
	if err := st.PruneAudit(1); err != nil {
		t.Fatal(err)
	}
	if _, status = requestAccessPage(t, s, "cursor="+url.QueryEscape(next)); status != 409 {
		t.Fatal("pruned anchor accepted", status)
	}
}
func TestAccessCursorBoundaries(t *testing.T) {
	now := time.Now().UTC()
	c := journalLogCursor{Kind: "access", From: now.Add(-time.Hour), To: now, Access: &accessLogPosition{MaxID: 350, ID: 250, Upper: "j0", Lower: "j99"}}
	data, _ := json.Marshal(c)
	token := base64.RawURLEncoding.EncodeToString(data)
	for _, query := range []string{"kind=vpn", "kind=services", "kind=access&from=" + url.QueryEscape(now.Add(-2*time.Hour).Format(time.RFC3339Nano))} {
		if _, err := journalPageRequest(httptest.NewRequest("GET", "/?"+query+"&cursor="+token, nil), now); err == nil {
			t.Fatal("cursor changed", query)
		}
	}
	if _, err := journalPageRequest(httptest.NewRequest("GET", "/?kind=access&cursor="+token, nil), now); err != nil {
		t.Fatal(err)
	}
}

func TestAccessJournalInclusiveAndStaleAnchors(t *testing.T) {
	raw := accessPageRow("j0", "noise") + "\n" + accessPageRow("j1", "noise")
	for _, skip := range []bool{false, true} {
		rows, stale, err := journalCandidateBatch(raw, "j0", skip, "SSH")
		expected := 2
		if skip {
			expected = 1
		}
		if err != nil || stale || len(rows) != expected {
			t.Fatal(skip, rows, stale, err)
		}
	}
	for _, raw := range []string{"", accessPageRow("j1", "noise")} {
		if _, stale, err := journalCandidateBatch(raw, "j0", false, "SSH"); err != nil || !stale {
			t.Fatal("unconsumed snapshot anchor vanished", stale, err)
		}
	}
	if _, _, err := journalCandidateBatch(`{"MESSAGE":"noise"}`, "", false, "SSH"); err == nil {
		t.Fatal("missing metadata ignored")
	}
}

func TestAccessMergeStopsAtIntervalFence(t *testing.T) {
	now := time.Now().UTC()
	rows := make([]logCandidate, 501)
	for i := range rows {
		var data map[string]json.RawMessage
		_ = json.Unmarshal([]byte(accessPageRow(fmt.Sprint("j", i), "Accepted publickey for alice from 192.0.2.1 port 42 ssh2")), &data)
		rows[i] = logCandidate{id: fmt.Sprint("j", i), at: now.Add(-time.Minute).UnixMicro(), journal: data}
	}
	// An old timestamp inside the interval's source boundaries is not EOF.
	rows[1].at = now.Add(-48 * time.Hour).UnixMicro()
	c := journalLogCursor{Kind: "access", From: now.Add(-time.Hour), To: now}
	pos := accessLogPosition{AuditDone: true, Upper: "j0", Lower: "j2"}
	p := journalLogPage{}
	if mergeAccessPage(&p, &c, &pos, rows, nil) || p.Next != "" || p.Scanned != 3 || len(p.Entries) != 2 {
		t.Fatal(p, pos)
	}
	// Losing the lower fence must request refresh, not silently claim EOF.
	pos = accessLogPosition{AuditDone: true, Upper: "j0", Lower: "removed"}
	p = journalLogPage{}
	if !mergeAccessPage(&p, &c, &pos, rows[:3], nil) {
		t.Fatal("missing lower fence accepted")
	}
}

func TestAccessMergeMatchesReferenceAcrossClockChanges(t *testing.T) {
	for seed := int64(0); seed < 150; seed++ {
		rng := rand.New(rand.NewSource(seed))
		base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
		c := journalLogCursor{Kind: "access", From: base, To: base.Add(time.Hour), Result: "failure", Object: "alice"}
		streams := [2][]logCandidate{}
		matches := map[string]bool{}
		for source := 0; source < 2; source++ {
			n := rng.Intn(1200)
			for i := 0; i < n; i++ {
				at := base.Add(time.Duration(rng.Intn(10800)-3600) * time.Second)
				user := "alice"
				if rng.Intn(3) == 0 {
					user = "bob"
				}
				success := rng.Intn(2) == 0
				row := logCandidate{at: at.UnixMicro()}
				var id string
				keep := true
				if source == 0 {
					row.id = fmt.Sprint("j", i)
					id = "journal:" + row.id
					verb := "Failed"
					if success {
						verb = "Accepted"
					}
					msg := verb + " password for " + user + " from 192.0.2.1 port 42 ssh2"
					if rng.Intn(3) == 0 {
						msg = "noise"
						keep = false
					}
					_ = json.Unmarshal([]byte(accessPageRow(row.id, msg)), &row.journal)
					row.journal["__REALTIME_TIMESTAMP"], _ = json.Marshal(strconv.FormatInt(row.at, 10))
				} else {
					row.audit = &store.AuditEntry{ID: int64(n - i), At: at, User: user, Action: "login", Success: success}
					id = "audit:" + strconv.FormatInt(row.audit.ID, 10)
				}
				matches[id] = keep && !success && user == "alice" && !at.Before(c.From) && !at.After(c.To)
				streams[source] = append(streams[source], row)
			}
		}
		// Independent unbounded head merge: source order, not wall-clock sorting.
		var expected []string
		x, y := 0, 0
		for x < len(streams[0]) || y < len(streams[1]) {
			id := ""
			if x < len(streams[0]) && (y == len(streams[1]) || streams[0][x].at >= streams[1][y].at) {
				id = "journal:" + streams[0][x].id
				x++
			} else {
				id = "audit:" + strconv.FormatInt(streams[1][y].audit.ID, 10)
				y++
			}
			if matches[id] {
				expected = append(expected, id)
			}
		}
		pos := accessLogPosition{MaxID: int64(len(streams[1]))}
		if len(streams[0]) > 0 {
			pos.Upper = "j0"
			pos.Lower = streams[0][len(streams[0])-1].id
		} else {
			pos.JournalDone = true
		}
		x, y = 0, 0
		var got []string
		for page := 0; page < 30; page++ {
			p := journalLogPage{Entries: []logEntry{}}
			if mergeAccessPage(&p, &c, &pos, streams[0][x:min(x+501, len(streams[0]))], streams[1][y:min(y+501, len(streams[1]))]) {
				t.Fatal("lower fence lost", seed)
			}
			if p.Scanned > 500 || len(p.Entries) > 100 || p.Incomplete {
				t.Fatal(seed, p)
			}
			for _, e := range p.Entries {
				got = append(got, e.ID)
			}
			if p.Next == "" {
				break
			}
			if !pos.valid(c.Anchor) {
				t.Fatal("invalid generated position", seed, pos, c.Anchor)
			}
			if pos.JournalDone {
				x = len(streams[0])
			} else if c.Anchor != "" {
				i, _ := strconv.Atoi(strings.TrimPrefix(c.Anchor, "j"))
				x = i + 1
			}
			if pos.AuditDone {
				y = len(streams[1])
			} else if pos.ID > 0 {
				y = len(streams[1]) - int(pos.ID) + 1
			}
		}
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("seed %d: got %d expected %d", seed, len(got), len(expected))
		}
	}
}
