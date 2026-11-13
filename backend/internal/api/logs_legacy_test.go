package api

// Historical readers remain only as comparison fixtures for regression tests.
// Production log endpoints use bounded pages and source cursors.
import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"
)

func parseJournalEntries(raw, source string) ([]logEntry, error) {
	result := []logEntry{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 2<<20)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var row map[string]json.RawMessage
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return result, fmt.Errorf("не удалось разобрать запись журнала")
		}
		if entry, keep := journalLogEntry(row, source); keep {
			result = append(result, entry)
		}
	}
	return result, scanner.Err()
}

func readDNSLog(path string, now time.Time) ([]logEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() {
		return nil, fmt.Errorf("источник DNS не является обычным файлом")
	}
	const maxBytes int64 = 256 << 10
	offset := stat.Size() - maxBytes
	if offset < 0 {
		offset = 0
	}
	if _, err = f.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	if offset > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	if len(lines) > 300 {
		lines = lines[len(lines)-300:]
	}
	result := []logEntry{}
	for _, line := range lines {
		if isDNSQuery(line) {
			result = append(result, logEntry{Time: dnsLineTime(line, now), Source: "dns", Unit: "dns.log", Message: line})
		}
	}
	return result, nil
}

func sortNewestFirst(entries []logEntry) {
	type keyed struct {
		at    time.Time
		known bool
		entry logEntry
	}
	rows := make([]keyed, len(entries))
	for i, e := range entries {
		at, _ := time.Parse(time.RFC3339Nano, e.Time)
		rows[i] = keyed{at: at, known: e.Time != "", entry: e}
	}
	slices.SortStableFunc(rows, func(a, b keyed) int {
		if a.known != b.known {
			if a.known {
				return -1
			}
			return 1
		}
		return b.at.Compare(a.at)
	})
	for i := range rows {
		entries[i] = rows[i].entry
	}
}

func emptyJournalMatch(raw string, err error) bool {
	var status interface{ ExitCode() int }
	return err != nil && errors.As(err, &status) && status.ExitCode() == 1 && strings.TrimSpace(raw) == "" && strings.HasSuffix(strings.TrimSpace(err.Error()), "exit status 1:")
}

func (s *Server) panelAccessEntries(ctx context.Context) ([]logEntry, error) {
	if s.Store == nil {
		return nil, fmt.Errorf("хранилище аудита недоступно")
	}
	rows, err := s.Store.ListAccessAudit(ctx, 300)
	if err != nil {
		return nil, err
	}
	out := make([]logEntry, 0, len(rows))
	for _, row := range rows {
		e, err := panelAccessEntry(row)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}
