package system

import (
	"context"
	"errors"
	"testing"
)

type failingRunner struct{ err error }

func (r *failingRunner) Run(context.Context, string, ...string) (string, error) {
	return "", r.err
}

func (r *failingRunner) RunInput(context.Context, string, string, ...string) (string, error) {
	return "", r.err
}

// Отсутствующий юнит для Disable — уже достигнутая цель, а не сбой. Пропущенная
// формулировка роняет всё применение и не даёт netosd запуститься: ровно так
// сломался запуск, когда unbound выбран не был, а его юнита ещё не было.
func TestDisableTreatsMissingUnitAsSuccess(t *testing.T) {
	messages := []string{
		"systemctl disable --now netos-unbound.service: exit status 1: Failed to disable unit: Unit netos-unbound.service does not exist",
		"systemctl disable --now x.service: exit status 5: Unit x.service not loaded.",
		"systemctl disable --now x.service: No such file or directory",
		"systemctl disable --now x.service: Unit x.service not found.",
	}
	for _, msg := range messages {
		s := NewSystemd(&failingRunner{err: errors.New(msg)})
		if err := s.Disable(context.Background(), "x.service"); err != nil {
			t.Errorf("отсутствующий юнит принят за ошибку: %v", err)
		}
	}
}

func TestDisableReportsRealFailure(t *testing.T) {
	s := NewSystemd(&failingRunner{err: errors.New("Failed to disable unit: Access denied")})
	if err := s.Disable(context.Background(), "x.service"); err == nil {
		t.Fatal("настоящая ошибка отключения потеряна")
	}
}
