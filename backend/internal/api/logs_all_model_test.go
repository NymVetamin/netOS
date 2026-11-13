package api

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/store"
)

func TestAllMergeMatchesFullHistoryWithClockJumps(t *testing.T) {
	type referenceRow struct {
		id   string
		at   int64
		keep bool
	}
	random := rand.New(rand.NewSource(74219))
	for trial := 0; trial < 100; trial++ {
		now := time.Now().UTC().Truncate(time.Second)
		c := journalLogCursor{Kind: "all", From: now.Add(-24 * time.Hour), To: now}
		var streams [4][]referenceRow
		var journal [2][]logCandidate
		var audit []store.AuditEntry
		var files []dnsFileLine
		var lookup [2]map[string]int
		for source := 0; source < 4; source++ {
			count := random.Intn(750)
			if source < 2 {
				lookup[source] = map[string]int{}
			}
			for i := 0; i < count; i++ {
				// Intentional backward/forward jumps and equal timestamps: source order
				// is authoritative, timestamps only compare currently available heads.
				at := now.Add(-time.Duration(random.Intn(40)) * time.Hour).UnixMicro()
				keep := random.Intn(4) == 0 || source == 2
				id := fmt.Sprintf("s%d-%d", source, i)
				switch source {
				case 0, 1:
					message := "noise"
					unit := "ssh.service"
					transport := "stdout"
					if source == 0 && keep {
						message = "Accepted publickey for alice from 192.0.2.1 port 42 ssh2"
					}
					if source == 1 {
						unit = ""
						transport = "kernel"
						if keep {
							message = "netos INPUT fixture"
						}
					}
					raw := map[string]json.RawMessage{}
					for k, v := range map[string]string{"__CURSOR": id, "__REALTIME_TIMESTAMP": strconv.FormatInt(at, 10), "_SYSTEMD_UNIT": unit, "_TRANSPORT": transport, "MESSAGE": message} {
						raw[k], _ = json.Marshal(v)
					}
					lookup[source][id] = i
					journal[source] = append(journal[source], logCandidate{id: id, at: at, journal: raw})
					id = "journal:" + id
				case 2:
					entry := store.AuditEntry{ID: int64(count - i), At: time.UnixMicro(at), Action: "login", User: "alice", Success: true}
					audit = append(audit, entry)
					id = "audit:" + strconv.FormatInt(entry.ID, 10)
				case 3:
					message := "noise"
					if keep {
						message = "query[A] repeated.example from 192.0.2.1"
					}
					files = append(files, dnsFileLine{ID: id, Text: time.UnixMicro(at).In(time.Local).Format("2006/01/02 15:04:05.000000") + " " + message, Next: dnsFileOffset{Offset: int64(count - i - 1)}})
					id = "file:" + id
				}
				streams[source] = append(streams[source], referenceRow{id: id, at: at, keep: keep})
			}
		}
		// Independent whole-history oracle, sorting only the four visible heads.
		indices := [4]int{}
		var want []string
		for {
			var heads []int
			for source := range streams {
				if indices[source] < len(streams[source]) {
					heads = append(heads, source)
				}
			}
			if len(heads) == 0 {
				break
			}
			sort.SliceStable(heads, func(i, j int) bool {
				return streams[heads[i]][indices[heads[i]]].at > streams[heads[j]][indices[heads[j]]].at
			})
			source := heads[0]
			row := streams[source][indices[source]]
			indices[source]++
			if row.keep && row.at >= c.From.UnixMicro() && row.at <= c.To.UnixMicro() {
				want = append(want, row.id)
			}
		}
		pos := allLogPosition{MaxID: int64(len(audit)), Files: &dnsFilePosition{Next: dnsFileOffset{Offset: int64(len(files))}}}
		pos.Files.Files[0] = dnsFileStamp{ID: "fixture", Size: int64(len(files))}
		for source := range journal {
			if len(journal[source]) == 0 {
				pos.Journal[source].Done = true
			} else {
				pos.Journal[source].Upper = journal[source][0].id
				pos.Journal[source].Lower = journal[source][len(journal[source])-1].id
			}
		}
		var got []string
		lastToken := ""
		for page := 0; page < 500; page++ {
			var batches [2][]logCandidate
			for source := range journal {
				if pos.Journal[source].Done {
					continue
				}
				start := 0
				if pos.Journal[source].Anchor != "" {
					start = lookup[source][pos.Journal[source].Anchor] + 1
				}
				batches[source] = journal[source][start:min(start+501, len(journal[source]))]
			}
			auditStart := 0
			if pos.ID > 0 {
				auditStart = len(audit) - int(pos.ID) + 1
			}
			fileStart := len(files) - int(pos.Files.Next.Offset)
			p := journalLogPage{Kind: "all", Entries: []logEntry{}, Warnings: []string{}, From: c.From, CapturedAt: c.To}
			stale, err := mergeAllLogPage(&p, &c, &pos, batches, audit[auditStart:min(auditStart+501, len(audit))], files[fileStart:min(fileStart+17, len(files))])
			if err != nil || stale || p.Incomplete || len(p.Entries) > 100 || p.Scanned > 500 {
				t.Fatalf("trial=%d page=%d err=%v stale=%v", trial, page, err, stale)
			}
			for _, e := range p.Entries {
				got = append(got, e.ID)
			}
			if p.Next == "" {
				break
			}
			if p.Next == lastToken || p.Scanned == 0 {
				t.Fatalf("no progress trial=%d page=%d", trial, page)
			}
			lastToken = p.Next
			if page == 499 {
				t.Fatal("page budget")
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("trial=%d got=%d want=%d", trial, len(got), len(want))
		}
	}
}
