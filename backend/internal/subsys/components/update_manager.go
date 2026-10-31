package components

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type UpdateSnapshot struct {
	CheckedAt  time.Time                  `json:"checked_at"`
	Components map[string]ComponentUpdate `json:"components"`
	Error      string                     `json:"error,omitempty"`
	Operation  Operation                  `json:"operation"`
	Operations map[string]Operation       `json:"operations,omitempty"`
}

// UpdateManager owns one daily timer and a cached snapshot. Reading the badge
// never starts processes or accesses a release server.
type UpdateManager struct {
	Subsystem  *Subsystem
	Path       string
	Run        func(context.Context, func() error) error
	mu         sync.Mutex
	busy       bool
	state      UpdateSnapshot
	operations map[string]Operation
}

func NewUpdateManager(s *Subsystem, path string) *UpdateManager {
	m := &UpdateManager{Subsystem: s, Path: path}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &m.state)
	}
	m.state.Operation = Operation{}
	m.state.Operations = nil
	s.OnChange = m.invalidate
	return m
}
func (m *UpdateManager) invalidate(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	affected := map[string]bool{id: true}
	packages := map[string]bool{}
	for _, c := range config.Catalog {
		if c.ID == id {
			for _, p := range c.Packages {
				packages[p] = true
			}
			break
		}
	}
	for _, c := range config.Catalog {
		for _, p := range c.Packages {
			if packages[p] {
				affected[c.ID] = true
				break
			}
		}
	}
	rows := make(map[string]ComponentUpdate, len(m.state.Components))
	for key, row := range m.state.Components {
		if !affected[key] {
			rows[key] = row
		}
	}
	if len(rows) == len(m.state.Components) {
		return
	}
	m.state.Components = rows
	data, _ := json.Marshal(m.state)
	if err := system.WriteFileAtomic(m.Path, data, 0600); err != nil {
		m.state.Error = fmt.Sprintf("сохранение состояния компонентов: %v", err)
	}
}
func (m *UpdateManager) Snapshot() UpdateSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := m.state
	result.Operation = m.Subsystem.Progress.Snapshot()
	if len(m.operations) > 0 || (result.Operation.Component != "" && result.Operation.Kind != "check") {
		result.Operations = make(map[string]Operation, len(m.operations)+1)
		for id, op := range m.operations {
			result.Operations[id] = op
		}
		if op := result.Operation; op.Component != "" && op.Kind != "check" {
			result.Operations[op.Component] = op
		}
	}
	if m.busy && !result.Operation.Active {
		result.Operation = Operation{Active: true, Stage: "Ожидание выполнения операции"}
	}
	return result // maps are immutable after publication
}
func (m *UpdateManager) Start(ctx context.Context, id, token string) error {
	if id != "" {
		return m.StartUpdates(ctx, []UpdateRequest{{ID: id, Token: token}})
	}
	return m.start(ctx, nil)
}

type UpdateRequest struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

func (m *UpdateManager) StartUpdates(ctx context.Context, requests []UpdateRequest) error {
	if len(requests) == 0 || len(requests) > len(config.Catalog) {
		return fmt.Errorf("выберите компоненты для обновления")
	}
	known := make(map[string]bool, len(config.Catalog))
	for _, c := range config.Catalog {
		known[c.ID] = true
	}
	for _, r := range requests {
		if !known[r.ID] || r.Token == "" {
			return fmt.Errorf("неизвестный или повторный компонент, либо отсутствует версия")
		}
		delete(known, r.ID)
	}
	return m.start(ctx, append([]UpdateRequest(nil), requests...))
}

func (m *UpdateManager) start(ctx context.Context, requests []UpdateRequest) error {
	m.mu.Lock()
	if m.busy {
		m.mu.Unlock()
		return fmt.Errorf("операция с компонентами уже выполняется")
	}
	m.busy = true
	m.operations = make(map[string]Operation, len(requests))
	for _, r := range requests {
		m.operations[r.ID] = Operation{Kind: "update", Component: r.ID, Status: "queued", Stage: "В очереди"}
	}
	m.mu.Unlock()
	go func() {
		defer func() { m.mu.Lock(); m.busy = false; m.mu.Unlock() }()
		ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		defer cancel()
		run := func() error {
			m.Subsystem.Progress.Start("check", "")
			var operationErr error
			defer func() { m.Subsystem.Progress.Finish(operationErr) }()
			if len(requests) > 0 {
				operationErr = m.runUpdates(ctx, requests)
				m.Subsystem.Progress.Start("check", "")
			}
			rows, err := m.Subsystem.checkUpdates(ctx, len(requests) == 0)
			if err != nil && operationErr == nil {
				operationErr = err
			}
			m.mu.Lock()
			if err == nil {
				for id, row := range rows {
					if row.Error != "" {
						if previous, ok := m.state.Components[id]; ok {
							previous.Error = row.Error
							rows[id] = previous
						}
					}
				}
				m.state.Components = rows
			}
			m.state.CheckedAt = time.Now()
			m.state.Error = ""
			if operationErr != nil {
				m.state.Error = operationErr.Error()
			}
			data, _ := json.Marshal(m.state)
			m.mu.Unlock()
			if err := system.WriteFileAtomic(m.Path, data, 0600); err != nil && operationErr == nil {
				operationErr = fmt.Errorf("сохранение проверки: %w", err)
			}
			return operationErr
		}
		var err error
		if m.Run != nil {
			err = m.Run(ctx, run)
		} else {
			err = run()
		}
		if err != nil {
			m.mu.Lock()
			m.state.Error = err.Error()
			for id, op := range m.operations {
				if op.Status == "queued" {
					op.Status, op.Stage = "cancelled", "Не запущено: очередь остановлена"
					m.operations[id] = op
				}
			}
			m.mu.Unlock()
		}
	}()
	return nil
}

func (m *UpdateManager) runUpdates(ctx context.Context, requests []UpdateRequest) error {
	ids := make([]string, len(requests))
	for i, r := range requests {
		ids[i] = r.ID
	}
	rows, err := m.Subsystem.checkUpdates(ctx, false, ids...)
	if err != nil {
		return err
	}
	// Validate all selected versions before installing anything, not midway.
	for _, r := range requests {
		row, ok := rows[r.ID]
		if !ok || row.Error != "" || !row.UpdateAvailable || row.Token != r.Token {
			return fmt.Errorf("%s: версии изменились или проверка не завершена; проверьте обновления ещё раз", r.ID)
		}
	}
	infos := make(map[string]config.ComponentInfo, len(config.Catalog))
	for _, c := range config.Catalog {
		infos[c.ID] = c
	}
	updated := map[string]bool{}
	owners := packageUnitPatterns()
	for _, r := range requests {
		if err := ctx.Err(); err != nil {
			return err
		}
		row := rows[r.ID]
		row.Packages = append([]PackageUpdate(nil), row.Packages...)
		needed := infos[r.ID].External
		for i := range row.Packages {
			p := &row.Packages[i]
			p.UpdateAvailable = p.UpdateAvailable && !updated[p.Name]
			needed = needed || p.UpdateAvailable
		}
		m.Subsystem.Progress.Start("update", r.ID)
		m.Subsystem.Progress.Stage(r.ID, "Подготовка обновления")
		var updateErr error
		if needed {
			updateErr = m.Subsystem.upgradePrepared(ctx, infos[r.ID], row, owners)
		}
		if updateErr == nil {
			for _, p := range row.Packages {
				if p.UpdateAvailable {
					updated[p.Name] = true
				}
			}
			m.Subsystem.Progress.Stage(r.ID, "Обновлено")
		}
		m.Subsystem.Progress.Finish(updateErr)
		m.mu.Lock()
		m.operations[r.ID] = m.Subsystem.Progress.Snapshot()
		m.mu.Unlock()
		if updateErr != nil {
			return errors.Join(fmt.Errorf("%s: обновление не выполнено", r.ID), updateErr)
		}
	}
	return nil
}
func (m *UpdateManager) Serve(ctx context.Context) {
	// Spread startup work away from boot; subsequent checks run at 03:00 local.
	delay := time.Minute
	if !m.Snapshot().CheckedAt.IsZero() && time.Since(m.Snapshot().CheckedAt) < 24*time.Hour {
		delay = untilNextCheck(time.Now())
	}
	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if err := m.Start(ctx, "", ""); err != nil {
			delay = 15 * time.Minute
		} else {
			delay = untilNextCheck(time.Now())
		}
	}
}
func untilNextCheck(now time.Time) time.Duration {
	next := time.Date(now.Year(), now.Month(), now.Day(), 3, 0, 0, 0, now.Location())
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next.Sub(now)
}
