package manage

import (
	"context"
	"strings"
	"testing"
)

func TestApplyOwnerArguments(t *testing.T) {
	for _, args := range [][]string{
		{"apply", "--user"}, {"apply", "--user", ""},
		{"apply", "--user", "--bad"}, {"apply", "--bad", "alice"},
		{"apply", "--user", "alice", "bob"}, {"confirm", "--user", "alice"},
	} {
		m, _ := testManager()
		if err := m.Execute(context.Background(), args); err == nil || !strings.Contains(err.Error(), "использование") {
			t.Fatalf("args=%v error=%v", args, err)
		}
	}
	m, _ := testManager()
	m.EUID = func() int { return 1000 }
	if err := m.Execute(context.Background(), []string{"apply", "--user", "alice"}); err == nil {
		t.Fatal("non-root apply accepted")
	}
}
