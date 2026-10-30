package components

import (
	"context"
	"encoding/json"
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
}

// UpdateManager owns one daily timer and a cached snapshot. Reading the badge
// never starts processes or accesses a release server.
type UpdateManager struct {
	Subsystem *Subsystem
	Path      string
	Run       func(context.Context, func() error) error
	mu        sync.Mutex
	busy      bool
	state     UpdateSnapshot
}

func NewUpdateManager(s *Subsystem, path string) *UpdateManager {
	m := &UpdateManager{Subsystem: s, Path: path}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &m.state)
	}
	m.state.Operation = Operation{}
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
	if m.busy && !result.Operation.Active {
		result.Operation = Operation{Active: true, Stage: "Ожидание выполнения операции"}
	}
	return result // maps are immutable after publication
}
func (m *UpdateManager) Start(ctx context.Context, id, token string) error {
	m.mu.Lock()
	if m.busy {
		m.mu.Unlock()
		return fmt.Errorf("операция с компонентами уже выполняется")
	}
	m.busy = true
	m.mu.Unlock()
	go func() {
		defer func() { m.mu.Lock(); m.busy = false; m.mu.Unlock() }()
		ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		defer cancel()
		run := func() error {
			kind := "check"
			if id != "" {
				kind = "update"
			}
			m.Subsystem.Progress.Start(kind, id)
			var operationErr error
			defer func() { m.Subsystem.Progress.Finish(operationErr) }()
			if id != "" {
				operationErr = m.Subsystem.Upgrade(ctx, id, token)
			}
			rows, err := m.Subsystem.checkUpdates(ctx, id == "")
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
			m.mu.Unlock()
		}
	}()
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
