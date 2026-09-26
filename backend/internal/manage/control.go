package manage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/netos-router/netos/internal/api"
)

type cliDraft struct {
	Dirty        bool   `json:"dirty"`
	DraftVersion uint64 `json:"draft_version"`
}

func (m *Manager) status(ctx context.Context) error {
	var state json.RawMessage
	statusCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := m.controlRequest(statusCtx, http.MethodGet, "/status", nil, &state); err != nil {
		fmt.Fprintf(m.Err, "Живая сводка недоступна: %v\n", err)
		fmt.Fprintf(m.Out, "netOS %s\n\n", displayVersion(m.Version))
		return m.run(ctx, "systemctl", "status", "--no-pager", "netosd")
	}
	encoder := json.NewEncoder(m.Out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(state)
}

type cliApplyResult struct {
	Revision     int64 `json:"revision"`
	NeedsConfirm bool  `json:"needs_confirm"`
}

func (m *Manager) controlRequest(ctx context.Context, method, path string, body any, result any) error {
	var input io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		input = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://netos.local"+path, input)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	socket := m.sys(api.ControlSocketPath)
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}, Timeout: 16 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("нет связи с работающим netosd: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var problem struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &problem) == nil && problem.Error != "" {
			return fmt.Errorf("%s", problem.Error)
		}
		return fmt.Errorf("netosd вернул HTTP %d", resp.StatusCode)
	}
	if result != nil {
		if err := json.Unmarshal(data, result); err != nil {
			return fmt.Errorf("ответ netosd: %w", err)
		}
	}
	return nil
}

func (m *Manager) applyDraft(ctx context.Context) error {
	var draft cliDraft
	if err := m.controlRequest(ctx, http.MethodGet, "/draft", nil, &draft); err != nil {
		return err
	}
	if !draft.Dirty {
		return fmt.Errorf("нет изменений в черновике")
	}
	var result cliApplyResult
	if err := m.controlRequest(ctx, http.MethodPost, "/apply", map[string]any{
		"draft_version": draft.DraftVersion,
		"comment":       "netos apply",
	}, &result); err != nil {
		return err
	}
	fmt.Fprintf(m.Out, "Ревизия %d применена.\n", result.Revision)
	if result.NeedsConfirm {
		fmt.Fprintln(m.Out, "Требуется подтверждение: netos confirm. Без него изменения будут автоматически отменены.")
	}
	return nil
}

func (m *Manager) confirmDraft(ctx context.Context) error {
	if err := m.controlRequest(ctx, http.MethodPost, "/confirm", map[string]any{}, nil); err != nil {
		return err
	}
	fmt.Fprintln(m.Out, "Изменения подтверждены.")
	return nil
}
