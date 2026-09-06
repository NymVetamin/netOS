package system

import (
	"context"
	"errors"
	"testing"
)

func TestReportResetFailedHandlesUnloadedUnit(t *testing.T) {
	for _, message := range []string{"Unit optional.service not loaded.", "Unit optional.service could not be found."} {
		if err := NewSystemd(&failingRunner{err: errors.New(message)}).ResetFailed(context.Background(), "optional.service"); err != nil {
			t.Fatal(err)
		}
	}
	if err := NewSystemd(&failingRunner{err: errors.New("Access denied")}).ResetFailed(context.Background(), "optional.service"); err == nil {
		t.Fatal("permission failure ignored")
	}
}
