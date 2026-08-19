package system

import (
	"context"
	"errors"
	"strings"
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

// scriptedRunner отвечает по командам, чтобы можно было изобразить службу,
// которая переживает disable.
type scriptedRunner struct {
	commands []string
	active   bool
}

func (r *scriptedRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	switch {
	case strings.HasPrefix(command, "systemctl is-active"):
		if r.active {
			return "active\n", nil
		}
		return "inactive\n", nil
	case strings.HasPrefix(command, "systemctl stop"):
		// Только stop действительно останавливает: так ведут себя службы,
		// унаследованные от SysV.
		r.active = false
	}
	return "", nil
}

func (r *scriptedRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

// systemctl disable для службы, унаследованной от SysV, перенаправляется в
// update-rc.d и демона не останавливает — даже с --now. Без отдельного stop
// чужой демон остался бы висеть на порту, который нужен netOS.
func TestDisableAlsoStopsSysVService(t *testing.T) {
	r := &scriptedRunner{active: true}
	if err := NewSystemd(r).Disable(context.Background(), "xl2tpd.service"); err != nil {
		t.Fatal(err)
	}
	var stopped bool
	for _, c := range r.commands {
		if strings.HasPrefix(c, "systemctl stop xl2tpd.service") {
			stopped = true
		}
	}
	if !stopped {
		t.Fatalf("остановка не выполнялась: %v", r.commands)
	}
	if r.active {
		t.Fatal("служба осталась работать")
	}
}

// Если после всего служба всё ещё работает, молчать нельзя: она держит порт.
func TestDisableReportsServiceThatSurvives(t *testing.T) {
	r := &scriptedRunner{active: true}
	// Изображаем службу, которую не берёт даже stop.
	stubborn := &stubbornRunner{scriptedRunner: r}
	if err := NewSystemd(stubborn).Disable(context.Background(), "x.service"); err == nil {
		t.Fatal("выжившая служба принята за остановленную")
	}
}

type stubbornRunner struct{ *scriptedRunner }

func (r *stubbornRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	if strings.HasPrefix(command, "systemctl is-active") {
		return "active\n", nil
	}
	r.commands = append(r.commands, command)
	return "", nil
}

func (r *stubbornRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}


// Штатный юнит успевает стартовать из postinst пакета и упасть на порту,
// который уже держит netOS. Погашенный, он навсегда остаётся в состоянии
// failed: systemctl показывает красную строку, а вся система — degraded, хотя
// ничего не сломано. Администратор идёт искать несуществующую поломку.
func TestDisableClearsFailedStateOfTheUnit(t *testing.T) {
	r := &scriptedRunner{active: true}
	if err := NewSystemd(r).Disable(context.Background(), "dnsmasq.service"); err != nil {
		t.Fatal(err)
	}
	var cleared bool
	for _, c := range r.commands {
		if strings.HasPrefix(c, "systemctl reset-failed dnsmasq.service") {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("состояние failed не сброшено: %v", r.commands)
	}
}
