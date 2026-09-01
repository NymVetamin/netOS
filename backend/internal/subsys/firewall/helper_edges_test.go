package firewall

import (
	"errors"
	"strings"
	"testing"
)

func TestJoinFirewallErrorPreservesCauseAndReportsRollback(t *testing.T) {
	cause := errors.New("apply failed")
	if got := joinFirewallError(cause, nil); !errors.Is(got, cause) || got != cause {
		t.Fatalf("nil rollback changed cause: %v", got)
	}
	got := joinFirewallError(cause, errors.New("restore failed"))
	if !errors.Is(got, cause) || !strings.Contains(got.Error(), "restore failed") {
		t.Fatalf("combined error=%v", got)
	}
}
