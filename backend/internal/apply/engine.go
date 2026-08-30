// Package apply приводит систему в состояние, описанное конфигурацией.
//
// Ключевая идея: применение — это транзакция. Пользователь может отрезать себе
// доступ одним неудачным правилом файрволла, поэтому после применения запускается
// таймер: если админ не подтвердил, что панель всё ещё отвечает, движок
// автоматически возвращает предыдущую ревизию.
package apply

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/netos-router/netos/internal/config"
)

// Subsystem — часть системы, которую netosd приводит в соответствие конфигу.
// Все реализации обязаны быть идемпотентными: повторный Apply с тем же
// конфигом не должен ничего менять и не должен рвать существующий трафик.
type Subsystem interface {
	Name() string
	// Plan возвращает человекочитаемый список изменений. Используется для
	// предпросмотра в UI и для журнала аудита. old может быть nil при первом
	// применении.
	Plan(old, new *config.Config) ([]Action, error)
	// Apply приводит подсистему к состоянию new.
	Apply(ctx context.Context, cfg *config.Config) error
	// Health проверяет, что подсистема после применения работает. Ошибка здесь
	// приводит к немедленному откату, не дожидаясь таймера подтверждения.
	Health(ctx context.Context, cfg *config.Config) error
}

// Action — одно запланированное изменение.
type Action struct {
	Subsystem string `json:"subsystem"`
	Kind      string `json:"kind"` // create | update | delete | reload | noop
	Target    string `json:"target"`
	Detail    string `json:"detail,omitempty"`
	// Disruptive помечает изменения, которые кратковременно рвут связность.
	// UI показывает такие отдельно и предупреждает.
	Disruptive bool `json:"disruptive"`
}

// Order задаёт порядок применения подсистем. Он не случаен: правила файрволла
// и политики маршрутизации ссылаются на интерфейсы, которых до создания
// каналов не существует, а DHCP-сервер не поднимется на интерфейсе без адреса.
var Order = []string{
	// Компоненты идут первыми: без установленных пакетов остальным подсистемам
	// нечего запускать.
	"components",
	"system",
	"sysctl",
	"ipv6",
	// netconf идёт перед подсистемами, назначающими адреса, и это существенно.
	// В режиме прямого управления он отбирает интерфейсы у systemd-networkd,
	// а тот при этом снимает выданные им адреса. Разрыв закрывается тем, что
	// interfaces, networks и wan назначают адреса netOS сразу следом.
	"netconf",
	"interfaces",
	"networks",
	"wan",
	"multiwan",
	"routing",
	"channels",
	"vpn-servers",
	"policy",
	"firewall",
	"dhcp",
	"dns",
	"wifi",
}

// connectivitySubsystems — подсистемы, изменение которых способно оборвать
// доступ администратора к панели: адреса, маршруты, правила файрволла,
// беспроводная сеть. Только их изменения требуют подтверждения после
// применения.
//
// Остальное подтверждать незачем. Смена сервера DHCP, резолвера, имени хоста
// или установка компонента связь с панелью не рвут: администратор, которому
// нечего проверять, получает окно с обратным отсчётом и вынужден нажимать
// «Всё работает» после каждой мелочи. Ценность подтверждения от этого падает —
// его начинают подтверждать не глядя, а именно оно спасает от правила
// файрволла, закрывшего доступ.
var connectivitySubsystems = map[string]bool{
	"netconf":     true,
	"interfaces":  true,
	"networks":    true,
	"wan":         true,
	"multiwan":    true,
	"routing":     true,
	"channels":    true,
	"policy":      true,
	"firewall":    true,
	"ipv6":        true,
	"wifi":        true,
	"vpn-servers": true,
}

// NeedsConfirmation сообщает, требует ли план подтверждения администратором.
//
// Пустой план подтверждать тоже нечего: применять нечего, значит и рваться
// нечему.
func NeedsConfirmation(actions []Action) bool {
	for _, a := range actions {
		if a.Disruptive || connectivitySubsystems[a.Subsystem] {
			return true
		}
	}
	return false
}

// RollbackInfo описывает состоявшийся откат. Панель показывает его
// администратору: иначе человек, не успевший подтвердить изменения, увидит
// лишь молча вернувшиеся старые настройки и не поймёт, что произошло.
type RollbackInfo struct {
	At       time.Time `json:"at"`
	Revision int64     `json:"revision"`
	// Reason: timeout — не дождались подтверждения, health — не прошла
	// проверка после применения, manual — откат по команде администратора.
	Reason  string `json:"reason"`
	Details string `json:"details,omitempty"`
}

// Engine оркестрирует применение конфигурации.
type Engine struct {
	// opMu сериализует все операции, меняющие живую систему. Обычный mu
	// защищает только состояние движка и не может удерживаться во время
	// медленных внешних команд.
	opMu       sync.Mutex
	mu         sync.Mutex
	subsystems map[string]Subsystem
	current    *config.Config

	// lastRollback хранит сведения о последнем откате до тех пор, пока
	// администратор их не увидит.
	lastRollback *RollbackInfo
	// OnRollback вызывается после отката: владелец движка обновляет состояние
	// ревизии в базе и журнал аудита.
	OnRollback func(RollbackInfo)

	// pending хранит состояние незавершённой транзакции: если админ не
	// подтвердит применение, движок вернёт previous.
	pending *pendingCommit
	log     Logger
	dryRun  bool
}

type pendingCommit struct {
	previous  *config.Config
	revision  int64
	deadline  time.Time
	timer     *time.Timer
	cancelled bool
}

// Logger — минимальный интерфейс журналирования, чтобы движок не зависел от
// конкретной библиотеки.
type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// NewEngine создаёт движок. dryRun печатает действия вместо выполнения —
// используется в тестах и при отладке на не-Linux машинах.
func NewEngine(log Logger, dryRun bool) *Engine {
	return &Engine{
		subsystems: map[string]Subsystem{},
		log:        log,
		dryRun:     dryRun,
	}
}

// Register добавляет подсистему. Имя должно присутствовать в Order, иначе
// подсистема никогда не будет применена.
func (e *Engine) Register(s Subsystem) error {
	for _, name := range Order {
		if name == s.Name() {
			e.subsystems[s.Name()] = s
			return nil
		}
	}
	return fmt.Errorf("подсистема %q отсутствует в порядке применения", s.Name())
}

// LastRollback возвращает сведения о последнем откате, если он был.
func (e *Engine) LastRollback() *RollbackInfo {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastRollback
}

// ClearRollback убирает отметку об откате — панель вызывает это, когда
// администратор прочитал сообщение.
func (e *Engine) ClearRollback() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastRollback = nil
}

// Current возвращает применённую сейчас конфигурацию.
func (e *Engine) Current() *config.Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.current
}

// Plan собирает планы всех подсистем в порядке применения.
func (e *Engine) Plan(new *config.Config) ([]Action, error) {
	e.mu.Lock()
	old := e.current
	e.mu.Unlock()
	return e.PlanFrom(old, new)
}

// PlanFrom строит план перехода между двумя заданными конфигурациями.
//
// Нужен там, где применённое состояние известно не движку, а вызывающему:
// команда netos plan работает отдельным процессом, своей истории применений у
// неё нет, и без явного old она сравнивала бы конфигурацию с пустотой — то
// есть всегда печатала бы план первой установки.
func (e *Engine) PlanFrom(old, new *config.Config) ([]Action, error) {
	if err := validateLiveTransition(old, new); err != nil {
		return nil, err
	}

	var actions []Action
	for _, name := range Order {
		s, ok := e.subsystems[name]
		if !ok {
			continue
		}
		sub, err := s.Plan(old, new)
		if err != nil {
			return nil, fmt.Errorf("план подсистемы %s: %w", name, err)
		}
		for i := range sub {
			sub[i].Subsystem = name
		}
		actions = append(actions, sub...)
	}
	return actions, nil
}

func validateLiveTransition(old, new *config.Config) error {
	if old == nil || new == nil {
		return nil
	}
	if old.System.Panel.Port != new.System.Panel.Port {
		return fmt.Errorf("порт панели нельзя менять без перезапуска netosd")
	}
	if old.System.Panel.TLS != new.System.Panel.TLS {
		return fmt.Errorf("параметры TLS панели нельзя менять без перезапуска netosd")
	}
	return nil
}

// Result описывает исход применения.
type Result struct {
	Applied      []Action  `json:"applied"`
	NeedsConfirm bool      `json:"needs_confirm"`
	Deadline     time.Time `json:"deadline,omitempty"`
	Revision     int64     `json:"revision"`
}

// Apply применяет конфигурацию целиком.
//
// Если needConfirm истинно, запускается таймер отката длиной
// cfg.System.Panel.CommitTimeout. Первое применение при загрузке системы
// подтверждения не требует: подтверждать некому.
func (e *Engine) Apply(ctx context.Context, cfg *config.Config, revision int64, needConfirm bool) (*Result, error) {
	e.opMu.Lock()
	defer e.opMu.Unlock()

	if res := cfg.Validate(); res.HasErrors() {
		return nil, fmt.Errorf("конфигурация не прошла проверку: %d ошибок", len(res.Problems))
	}

	e.mu.Lock()
	// Незавершённая транзакция блокирует новую: иначе откат вернёт не то,
	// что ожидает пользователь.
	if e.pending != nil {
		e.mu.Unlock()
		return nil, fmt.Errorf("предыдущее применение ещё не подтверждено")
	}
	previous := e.current
	e.mu.Unlock()

	actions, err := e.Plan(cfg)
	if err != nil {
		return nil, err
	}

	if err := e.run(ctx, cfg); err != nil {
		// Применение упало на середине — система в промежуточном состоянии,
		// немедленно возвращаемся к предыдущему конфигу.
		e.log.Errorf("применение не удалось: %v", err)
		if previous != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			if rbErr := e.run(rollbackCtx, previous); rbErr != nil {
				return nil, fmt.Errorf("применение не удалось (%w) и откат тоже не удался: %v", err, rbErr)
			}
			e.log.Warnf("выполнен откат к предыдущей конфигурации")
		}
		return nil, err
	}

	if err := e.health(ctx, cfg); err != nil {
		e.log.Errorf("проверка после применения не прошла: %v", err)
		if previous != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			if rbErr := e.run(rollbackCtx, previous); rbErr != nil {
				return nil, fmt.Errorf("проверка не прошла (%w) и откат не удался: %v", err, rbErr)
			}
		}
		return nil, fmt.Errorf("проверка после применения не прошла: %w", err)
	}

	e.mu.Lock()
	e.current = cfg
	res := &Result{Applied: actions, Revision: revision}

	if needConfirm && previous != nil && NeedsConfirmation(actions) {
		timeout := time.Duration(cfg.System.Panel.CommitTimeout) * time.Second
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		p := &pendingCommit{
			previous: previous,
			revision: revision,
			deadline: time.Now().Add(timeout),
		}
		p.timer = time.AfterFunc(timeout, func() { e.rollbackExpired(p) })
		e.pending = p
		res.NeedsConfirm = true
		res.Deadline = p.deadline
		e.log.Infof("конфигурация применена, ожидается подтверждение в течение %s", timeout)
	}
	e.mu.Unlock()

	return res, nil
}

// Confirm подтверждает, что админ по-прежнему имеет доступ, и отменяет откат.
func (e *Engine) Confirm(commit func(int64) error) (int64, error) {
	e.opMu.Lock()
	defer e.opMu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pending == nil {
		return 0, fmt.Errorf("нет применения, ожидающего подтверждения")
	}
	revision := e.pending.revision
	if commit != nil {
		if err := commit(revision); err != nil {
			return 0, fmt.Errorf("фиксация ревизии %d: %w", revision, err)
		}
	}
	e.pending.timer.Stop()
	e.pending.cancelled = true
	e.pending = nil
	e.log.Infof("применение подтверждено")
	return revision, nil
}

// Pending сообщает, ожидается ли подтверждение и до какого момента.
func (e *Engine) Pending() (bool, time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pending == nil {
		return false, time.Time{}
	}
	return true, e.pending.deadline
}

// Rollback немедленно возвращает предыдущую конфигурацию по явной команде.
func (e *Engine) Rollback(ctx context.Context) error {
	e.mu.Lock()
	p := e.pending
	e.mu.Unlock()
	if p == nil {
		return fmt.Errorf("нечего откатывать")
	}
	p.timer.Stop()
	return e.doRollback(ctx, p, "manual", "откат по команде администратора")
}

// errRollbackObsolete означает, что откатывать уже нечего: администратор успел
// подтвердить применение, пока таймер ждал opMu. Это штатная гонка, а не сбой,
// и в журнал она попадать не должна.
var errRollbackObsolete = errors.New("откат уже завершён или отменён")

func (e *Engine) rollbackExpired(p *pendingCommit) {
	e.mu.Lock()
	if p.cancelled || e.pending != p {
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()

	e.log.Warnf("подтверждение не получено, откат к предыдущей конфигурации")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	err := e.doRollback(ctx, p, "timeout", "подтверждение не получено в отведённое время")
	switch {
	case errors.Is(err, errRollbackObsolete):
		e.log.Infof("откат отменён: применение подтверждено вовремя")
	case err != nil:
		e.log.Errorf("автоматический откат не удался: %v", err)
	}
}

func (e *Engine) doRollback(ctx context.Context, p *pendingCommit, reason, details string) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()

	e.mu.Lock()
	if e.pending != p || p.cancelled {
		e.mu.Unlock()
		return errRollbackObsolete
	}
	e.mu.Unlock()

	if err := e.run(ctx, p.previous); err != nil {
		return err
	}

	info := RollbackInfo{
		At:       time.Now(),
		Revision: p.revision,
		Reason:   reason,
		Details:  details,
	}

	e.mu.Lock()
	e.current = p.previous
	if e.pending == p {
		e.pending = nil
	}
	e.lastRollback = &info
	callback := e.OnRollback
	e.mu.Unlock()

	if callback != nil {
		callback(info)
	}
	e.log.Infof("откат выполнен: %s", details)
	return nil
}

func (e *Engine) run(ctx context.Context, cfg *config.Config) error {
	for _, name := range Order {
		s, ok := e.subsystems[name]
		if !ok {
			continue
		}
		if e.dryRun {
			e.log.Infof("[dry-run] подсистема %s", name)
			continue
		}
		start := time.Now()
		if err := s.Apply(ctx, cfg); err != nil {
			return fmt.Errorf("подсистема %s: %w", name, err)
		}
		e.log.Infof("подсистема %s применена за %s", name, time.Since(start).Round(time.Millisecond))
	}
	return nil
}

func (e *Engine) health(ctx context.Context, cfg *config.Config) error {
	if e.dryRun {
		return nil
	}
	for _, name := range Order {
		s, ok := e.subsystems[name]
		if !ok {
			continue
		}
		if err := s.Health(ctx, cfg); err != nil {
			return fmt.Errorf("подсистема %s: %w", name, err)
		}
	}
	return nil
}
