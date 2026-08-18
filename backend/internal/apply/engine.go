// Package apply приводит систему в состояние, описанное конфигурацией.
//
// Ключевая идея: применение — это транзакция. Пользователь может отрезать себе
// доступ одним неудачным правилом файрволла, поэтому после применения запускается
// таймер: если админ не подтвердил, что панель всё ещё отвечает, движок
// автоматически возвращает предыдущую ревизию.
package apply

import (
	"context"
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
	"sysctl",
	"ipv6",
	"interfaces",
	"networks",
	"wan",
	"routing",
	"channels",
	"vpn-servers",
	"policy",
	"firewall",
	"dhcp",
	"dns",
	"wifi",
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
	pending  *pendingCommit
	log      Logger
	dryRun   bool
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
			if rbErr := e.run(ctx, previous); rbErr != nil {
				return nil, fmt.Errorf("применение не удалось (%w) и откат тоже не удался: %v", err, rbErr)
			}
			e.log.Warnf("выполнен откат к предыдущей конфигурации")
		}
		return nil, err
	}

	if err := e.health(ctx, cfg); err != nil {
		e.log.Errorf("проверка после применения не прошла: %v", err)
		if previous != nil {
			if rbErr := e.run(ctx, previous); rbErr != nil {
				return nil, fmt.Errorf("проверка не прошла (%w) и откат не удался: %v", err, rbErr)
			}
		}
		return nil, fmt.Errorf("проверка после применения не прошла: %w", err)
	}

	e.mu.Lock()
	e.current = cfg
	res := &Result{Applied: actions, Revision: revision}

	if needConfirm && previous != nil {
		timeout := time.Duration(cfg.System.Panel.CommitTimeout) * time.Second
		if timeout <= 0 {
			timeout = 90 * time.Second
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
func (e *Engine) Confirm() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pending == nil {
		return fmt.Errorf("нет применения, ожидающего подтверждения")
	}
	e.pending.timer.Stop()
	e.pending.cancelled = true
	e.pending = nil
	e.log.Infof("применение подтверждено")
	return nil
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
	if err := e.doRollback(ctx, p, "timeout", "подтверждение не получено в отведённое время"); err != nil {
		e.log.Errorf("автоматический откат не удался: %v", err)
	}
}

func (e *Engine) doRollback(ctx context.Context, p *pendingCommit, reason, details string) error {
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
