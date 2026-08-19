package apply

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/config"
)

type testLogger struct{}

func (testLogger) Infof(string, ...any)  {}
func (testLogger) Warnf(string, ...any)  {}
func (testLogger) Errorf(string, ...any) {}

type testSubsystem struct {
	apply func(context.Context, *config.Config) error
}

func (s *testSubsystem) Name() string { return "interfaces" }

// Plan сообщает об изменении адресации: подтверждения после применения требуют
// только те подсистемы, что способны оборвать доступ к панели, и без такого
// действия движок не стал бы заводить транзакцию вовсе.
func (s *testSubsystem) Plan(*config.Config, *config.Config) ([]Action, error) {
	return []Action{{Kind: "update", Target: "eth0", Disruptive: true}}, nil
}
func (s *testSubsystem) Apply(ctx context.Context, cfg *config.Config) error {
	if s.apply != nil {
		return s.apply(ctx, cfg)
	}
	return nil
}
func (s *testSubsystem) Health(context.Context, *config.Config) error { return nil }

func newTestEngine(t *testing.T, subsystem *testSubsystem) *Engine {
	t.Helper()
	e := NewEngine(testLogger{}, false)
	if err := e.Register(subsystem); err != nil {
		t.Fatal(err)
	}
	return e
}

func validConfig(host string) *config.Config {
	cfg := config.Default()
	cfg.System.Hostname = host
	cfg.System.Panel.CommitTimeout = 60
	return cfg
}

func TestConfirmCommitsPendingRevision(t *testing.T) {
	e := newTestEngine(t, &testSubsystem{})
	if _, err := e.Apply(context.Background(), validConfig("initial"), 1, false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(context.Background(), validConfig("next"), 42, true); err != nil {
		t.Fatal(err)
	}

	committed := int64(0)
	revision, err := e.Confirm(func(id int64) error {
		committed = id
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if revision != 42 || committed != 42 {
		t.Fatalf("подтверждена ревизия %d, callback получил %d; нужна 42", revision, committed)
	}
}

func TestConcurrentApplyIsSerialized(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var active, maximum atomic.Int32
	sub := &testSubsystem{apply: func(ctx context.Context, cfg *config.Config) error {
		n := active.Add(1)
		defer active.Add(-1)
		for {
			old := maximum.Load()
			if n <= old || maximum.CompareAndSwap(old, n) {
				break
			}
		}
		if cfg.System.Hostname == "second" {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}}
	e := newTestEngine(t, sub)
	if _, err := e.Apply(context.Background(), validConfig("initial"), 1, false); err != nil {
		t.Fatal(err)
	}

	firstDone := make(chan error, 1)
	go func() {
		_, err := e.Apply(context.Background(), validConfig("second"), 2, true)
		firstDone <- err
	}()
	<-entered

	secondDone := make(chan error, 1)
	go func() {
		_, err := e.Apply(context.Background(), validConfig("third"), 3, true)
		secondDone <- err
	}()

	select {
	case <-secondDone:
		t.Fatal("второе применение прошло мимо блокировки")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err == nil {
		t.Fatal("второе применение должно быть отклонено из-за pending commit")
	}
	if maximum.Load() != 1 {
		t.Fatalf("одновременно выполнялось подсистем: %d", maximum.Load())
	}
}

func TestFailedApplyRollsBackWithLiveContext(t *testing.T) {
	rollbackHadLiveContext := false
	initialApplied := false
	sub := &testSubsystem{apply: func(ctx context.Context, cfg *config.Config) error {
		if cfg.System.Hostname == "initial" {
			if initialApplied {
				rollbackHadLiveContext = ctx.Err() == nil
			}
			initialApplied = true
			return nil
		}
		return ctx.Err()
	}}
	e := newTestEngine(t, sub)
	if _, err := e.Apply(context.Background(), validConfig("initial"), 1, false); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Apply(cancelled, validConfig("broken"), 2, true); err == nil {
		t.Fatal("ожидалась ошибка отменённого применения")
	}
	if !rollbackHadLiveContext {
		t.Fatal("откат унаследовал отменённый контекст применения")
	}
}

func TestLivePanelPortChangeIsRejectedBeforeApply(t *testing.T) {
	calls := 0
	sub := &testSubsystem{apply: func(context.Context, *config.Config) error {
		calls++
		return nil
	}}
	e := newTestEngine(t, sub)
	initial := validConfig("initial")
	if _, err := e.Apply(context.Background(), initial, 1, false); err != nil {
		t.Fatal(err)
	}
	calls = 0
	changed := validConfig("initial")
	changed.System.Panel.Port++
	if _, err := e.Apply(context.Background(), changed, 2, true); err == nil {
		t.Fatal("смена порта работающей панели прошла без ошибки")
	}
	if calls != 0 {
		t.Fatalf("до отказа успело выполниться применений: %d", calls)
	}
}

// safeSubsystem меняет то, что связь с панелью оборвать не может: резолвер.
type safeSubsystem struct{}

func (safeSubsystem) Name() string { return "dns" }
func (safeSubsystem) Plan(*config.Config, *config.Config) ([]Action, error) {
	return []Action{{Kind: "update", Target: "DNS-резолвер"}}, nil
}
func (safeSubsystem) Apply(context.Context, *config.Config) error  { return nil }
func (safeSubsystem) Health(context.Context, *config.Config) error { return nil }

// TestHarmlessChangeNeedsNoConfirmation закрепляет, что окно с обратным
// отсчётом появляется не после всякого применения. Смена резолвера или сервера
// DHCP связь с панелью не рвёт, и требовать подтверждения там — приучать
// администратора нажимать «Всё работает» не глядя.
func TestHarmlessChangeNeedsNoConfirmation(t *testing.T) {
	e := NewEngine(testLogger{}, false)
	if err := e.Register(safeSubsystem{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(context.Background(), validConfig("initial"), 1, false); err != nil {
		t.Fatal(err)
	}
	res, err := e.Apply(context.Background(), validConfig("next"), 2, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.NeedsConfirm {
		t.Fatal("подтверждения потребовало изменение, которое не может оборвать доступ")
	}
	if pending, _ := e.Pending(); pending {
		t.Fatal("движок оставил незавершённую транзакцию и заблокировал следующее применение")
	}
}

// TestConnectivityChangeStillNeedsConfirmation — обратная сторона: изменение
// адресации по-прежнему обязано ждать подтверждения, иначе теряется вся защита
// от правила, закрывшего администратору доступ.
func TestConnectivityChangeStillNeedsConfirmation(t *testing.T) {
	e := newTestEngine(t, &testSubsystem{})
	if _, err := e.Apply(context.Background(), validConfig("initial"), 1, false); err != nil {
		t.Fatal(err)
	}
	res, err := e.Apply(context.Background(), validConfig("next"), 2, true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.NeedsConfirm {
		t.Fatal("изменение адресации применилось без подтверждения")
	}
}
