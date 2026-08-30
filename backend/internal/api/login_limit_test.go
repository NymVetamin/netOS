package api

import (
	"fmt"
	"testing"
	"time"
)

func TestLoginFailuresExpire(t *testing.T) {
	s := &Server{loginFails: map[string]*failCounter{
		"old": {count: 9, until: time.Now().Add(time.Hour), last: time.Now().Add(-loginFailureTTL - time.Minute)},
	}}
	if _, blocked := s.loginBlocked("old"); blocked {
		t.Fatal("устаревшая блокировка продолжает действовать")
	}
	if len(s.loginFails) != 0 {
		t.Fatal("устаревшая запись не удалена")
	}
}

func TestLoginFailureTableIsBounded(t *testing.T) {
	s := &Server{loginFails: map[string]*failCounter{}}
	for i := 0; i < maxLoginSources+100; i++ {
		s.recordLoginFailure(fmt.Sprintf("192.0.2.%d", i))
	}
	if len(s.loginFails) != maxLoginSources {
		t.Fatalf("таблица выросла до %d, предел %d", len(s.loginFails), maxLoginSources)
	}
}

func TestPruneLoginFailuresKeepsRecentEntries(t *testing.T) {
	now := time.Now()
	s := &Server{loginFails: map[string]*failCounter{
		"old":    {last: now.Add(-loginFailureTTL - time.Second)},
		"recent": {last: now.Add(-time.Minute)},
	}}
	s.pruneLoginFailures(now)
	if _, ok := s.loginFails["old"]; ok {
		t.Fatal("старая запись осталась")
	}
	if _, ok := s.loginFails["recent"]; !ok {
		t.Fatal("свежая запись удалена")
	}
}
