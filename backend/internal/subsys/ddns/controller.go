// Package ddns updates public DNS records without exposing provider secrets on
// a process command line or in generated systemd units.
package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type Logger interface {
	Infof(string, ...any)
	Warnf(string, ...any)
}

type Status struct {
	Enabled  bool      `json:"enabled"`
	LastRun  time.Time `json:"last_run,omitzero"`
	NextRun  time.Time `json:"next_run,omitzero"`
	Address  string    `json:"address,omitempty"`
	Success  bool      `json:"success"`
	Message  string    `json:"message,omitempty"`
	Provider string    `json:"provider,omitempty"`
	Hostname string    `json:"hostname,omitempty"`
}

type Controller struct {
	Client          *http.Client
	Logger          Logger
	DuckEndpoint    string
	CloudEndpoint   string
	NoIPEndpoint    string
	AddressEndpoint string
	ResolveAddress  func(context.Context, *config.Config) (string, error)
	InterfaceAddrs  func(string) ([]net.Addr, error)
	Now             func() time.Time
	TickInterval    time.Duration
	NoIPRetryPath   string

	mu             sync.RWMutex
	status         Status
	configured     config.DDNS
	configuredSet  bool
	suspended      bool
	noIPRetrySaved bool
	cancelTick     context.CancelFunc
}

func New(logger Logger) *Controller {
	c := &Controller{
		Client:          &http.Client{Timeout: 15 * time.Second},
		Logger:          logger,
		DuckEndpoint:    "https://www.duckdns.org/update",
		CloudEndpoint:   "https://api.cloudflare.com/client/v4",
		NoIPEndpoint:    "https://dynupdate.no-ip.com/nic/update",
		AddressEndpoint: "https://api.ipify.org",
		Now:             time.Now,
		TickInterval:    time.Second,
	}
	c.ResolveAddress = c.resolveAddress
	c.InterfaceAddrs = func(name string) ([]net.Addr, error) {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return nil, err
		}
		return iface.Addrs()
	}
	return c
}

func (c *Controller) Name() string { return "ddns" }

func (c *Controller) Plan(old, next *config.Config) ([]apply.Action, error) {
	var before config.DDNS
	if old != nil {
		before = old.DDNS
	}
	if reflect.DeepEqual(before, next.DDNS) {
		return nil, nil
	}
	kind := "update"
	if next.DDNS.Enabled && !before.Enabled {
		kind = "create"
	} else if !next.DDNS.Enabled {
		kind = "delete"
	}
	return []apply.Action{{Subsystem: c.Name(), Kind: kind, Target: "динамический DNS", Detail: next.DDNS.Hostname}}, nil
}

func (c *Controller) Apply(_ context.Context, cfg *config.Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.configuredSet && reflect.DeepEqual(c.configured, cfg.DDNS) {
		return nil
	}
	if c.cancelTick != nil {
		c.cancelTick()
	}
	c.configured = cfg.DDNS
	c.configuredSet = true
	c.suspended = false
	c.status = Status{Enabled: cfg.DDNS.Enabled, Provider: cfg.DDNS.Provider, Hostname: cfg.DDNS.Hostname}
	if cfg.DDNS.Enabled && cfg.DDNS.Provider == "noip" && c.NoIPRetryPath != "" {
		c.restoreNoIPRetry(cfg.DDNS)
	}
	return nil
}

const noIPBackoff = 30 * time.Minute

type noIPRetry struct {
	ProviderDeadline time.Time
	NextRun          time.Time
	Hostname         string
	Interval         int
}

// Called with mu held, only when applying a changed configuration.
func (c *Controller) restoreNoIPRetry(cfg config.DDNS) {
	var saved noIPRetry
	f, err := os.Open(c.NoIPRetryPath)
	if errors.Is(err, os.ErrNotExist) {
		c.noIPRetrySaved = false
		return
	}
	c.noIPRetrySaved = true
	if err == nil {
		var data []byte
		data, err = readLimited(f, 4096)
		f.Close()
		if err == nil {
			err = json.Unmarshal(data, &saved)
		}
		if err == nil && (saved.ProviderDeadline.IsZero() || saved.NextRun.Before(saved.ProviderDeadline)) {
			err = errors.New("отсутствует корректный срок")
		}
	}
	now := c.Now()
	if err != nil {
		c.status.NextRun = now.Add(noIPBackoff)
		c.status.Message = fmt.Sprintf("Не удалось прочитать срок повтора No-IP: %v", err)
		if c.Logger != nil {
			c.Logger.Warnf("%s", c.status.Message)
		}
		return
	}
	next := saved.ProviderDeadline
	if saved.Hostname == cfg.Hostname && saved.Interval == cfg.Interval {
		next = saved.NextRun
	}
	if now.Before(next) {
		c.status.NextRun = next
		c.status.Message = "Ожидание повторной попытки после временного отказа No-IP"
	}
}

// External DNS availability must not roll back unrelated router settings. The
// controller reports failures in Status and retries on schedule.
func (c *Controller) Health(context.Context, *config.Config) error { return nil }

func (c *Controller) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

func (c *Controller) Run(ctx context.Context, current func() *config.Config) {
	interval := c.TickInterval
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.tick(ctx, current())
		}
	}
}

func (c *Controller) tick(ctx context.Context, cfg *config.Config) {
	if cfg == nil || !cfg.DDNS.Enabled {
		return
	}
	c.mu.Lock()
	next := c.status.NextRun
	if c.cancelTick != nil || c.suspended || (!next.IsZero() && c.Now().Before(next)) ||
		(c.configuredSet && !reflect.DeepEqual(c.configured, cfg.DDNS)) {
		c.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	c.cancelTick = cancel
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		cancel()
		c.cancelTick = nil
		c.mu.Unlock()
	}()
	interval := time.Duration(cfg.DDNS.Interval) * time.Second
	if interval < time.Minute {
		interval = time.Minute
	}
	now := c.Now()
	address, err := c.ResolveAddress(ctx, cfg)
	if ctx.Err() != nil {
		return
	}
	if err == nil && cfg.DDNS.Provider == "noip" {
		c.mu.Lock()
		if ctx.Err() == nil && c.status.Success && c.status.Address == address {
			c.status.NextRun = now.Add(interval)
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
	}
	if err == nil {
		err = c.update(ctx, cfg.DDNS, address)
	}
	suspend := false
	next = now.Add(interval)
	var providerDeadline time.Time
	var providerFailure *providerError
	if errors.As(err, &providerFailure) {
		suspend = providerFailure.suspend
		if providerFailure.retryAfter > 0 {
			providerDeadline = c.Now().Add(providerFailure.retryAfter)
			if providerDeadline.After(next) {
				next = providerDeadline
			}
		}
	}
	status := Status{
		Enabled: true, LastRun: now, NextRun: next, Address: address,
		Success: err == nil, Provider: cfg.DDNS.Provider, Hostname: cfg.DDNS.Hostname,
	}
	if err != nil {
		status.Message = err.Error()
	}
	c.mu.Lock()
	// A provider request can outlive a concurrent configuration Apply. Never
	// let a response for the old credentials/record overwrite the new status.
	accepted := ctx.Err() == nil
	if accepted {
		if !providerDeadline.IsZero() && c.NoIPRetryPath != "" {
			saved := noIPRetry{ProviderDeadline: providerDeadline, NextRun: next, Hostname: cfg.DDNS.Hostname, Interval: cfg.DDNS.Interval}
			data, writeErr := json.Marshal(saved)
			if writeErr == nil {
				writeErr = system.WriteFileAtomic(c.NoIPRetryPath, data, 0600)
			}
			if writeErr != nil {
				err = fmt.Errorf("%w; не удалось сохранить срок повтора No-IP: %v", err, writeErr)
				status.Message = err.Error()
			} else {
				c.noIPRetrySaved = true
			}
		} else if err == nil && cfg.DDNS.Provider == "noip" && c.noIPRetrySaved {
			if removeErr := os.Remove(c.NoIPRetryPath); removeErr == nil || errors.Is(removeErr, os.ErrNotExist) {
				c.noIPRetrySaved = false
			} else if c.Logger != nil {
				c.Logger.Warnf("Не удалось удалить прежний срок повтора No-IP: %v", removeErr)
			}
		}
		c.status = status
		c.suspended = suspend
		if suspend {
			c.status.NextRun = time.Time{}
		}
	}
	c.mu.Unlock()
	if !accepted || c.Logger == nil {
		return
	}
	if err != nil {
		c.Logger.Warnf("DDNS %s: %v", cfg.DDNS.Hostname, err)
	} else {
		c.Logger.Infof("DDNS %s обновлён: %s", cfg.DDNS.Hostname, address)
	}
}

type providerError struct {
	message    string
	retryAfter time.Duration
	suspend    bool
}

func (e *providerError) Error() string { return e.message }

func (c *Controller) resolveAddress(ctx context.Context, cfg *config.Config) (string, error) {
	if cfg.DDNS.AddressSource == "web" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.AddressEndpoint, nil)
		if err != nil {
			return "", err
		}
		resp, err := c.Client.Do(req)
		if err != nil {
			return "", fmt.Errorf("определение внешнего адреса: %w", err)
		}
		defer resp.Body.Close()
		body, err := readLimited(resp.Body, 128)
		if err != nil {
			return "", fmt.Errorf("чтение ответа сервиса адреса: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("сервис адреса ответил HTTP %d", resp.StatusCode)
		}
		return validIPv4(strings.TrimSpace(string(body)))
	}
	name := ""
	interfaces := map[string]string{}
	for _, item := range cfg.Interfaces {
		interfaces[item.ID] = item.Name
	}
	for _, wan := range cfg.WANs {
		if wan.ID != cfg.DDNS.WAN {
			continue
		}
		name = interfaces[wan.Interface]
		if wan.Proto == "pppoe" || wan.Proto == "l2tp" {
			name = "ppp-" + wan.ID
		}
	}
	addrs, err := c.InterfaceAddrs(name)
	if err != nil {
		return "", fmt.Errorf("интерфейс %s: %w", name, err)
	}
	for _, item := range addrs {
		ip, _, err := net.ParseCIDR(item.String())
		if err == nil && ip.To4() != nil {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("на интерфейсе %s нет адреса IPv4", name)
}

func validIPv4(value string) (string, error) {
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("получен некорректный адрес IPv4")
	}
	return ip.To4().String(), nil
}

func (c *Controller) update(ctx context.Context, cfg config.DDNS, address string) error {
	var req *http.Request
	var err error
	switch cfg.Provider {
	case "duckdns":
		host := strings.TrimSuffix(strings.ToLower(cfg.Hostname), ".duckdns.org")
		values := url.Values{"domains": {host}, "token": {cfg.Token}, "ip": {address}}
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, c.DuckEndpoint+"?"+values.Encode(), nil)
	case "cloudflare":
		// PATCH and an omitted proxied field preserve the operator's Cloudflare
		// proxy setting. PUT would overwrite the whole record.
		body, _ := json.Marshal(map[string]any{"type": "A", "name": cfg.Hostname, "content": address})
		endpoint := fmt.Sprintf("%s/zones/%s/dns_records/%s", strings.TrimRight(c.CloudEndpoint, "/"), url.PathEscape(cfg.ZoneID), url.PathEscape(cfg.RecordID))
		req, err = http.NewRequestWithContext(ctx, http.MethodPatch, endpoint, bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+cfg.Token)
			req.Header.Set("Content-Type", "application/json")
		}
	case "noip":
		values := url.Values{"hostname": {cfg.Hostname}, "myip": {address}}
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, c.NoIPEndpoint+"?"+values.Encode(), nil)
		if err == nil {
			req.SetBasicAuth(cfg.Username, cfg.Password)
			req.Header.Set("User-Agent", "netOS/1.0 admin@localhost")
		}
	default:
		return fmt.Errorf("неизвестный провайдер %q", cfg.Provider)
	}
	if err != nil {
		return err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("запрос к провайдеру: %s", redactedProviderError(err, cfg))
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if cfg.Provider == "noip" {
			if resp.StatusCode == http.StatusInternalServerError {
				return &providerError{message: fmt.Sprintf("провайдер ответил HTTP %d", resp.StatusCode), retryAfter: noIPBackoff}
			}
			return &providerError{message: fmt.Sprintf("провайдер ответил HTTP %d; обновления приостановлены до изменения настройки", resp.StatusCode), suspend: true}
		}
		return fmt.Errorf("провайдер ответил HTTP %d", resp.StatusCode)
	}
	body, err := readLimited(resp.Body, 4096)
	if err != nil {
		return fmt.Errorf("чтение ответа провайдера: %w", err)
	}
	text := strings.TrimSpace(string(body))
	switch cfg.Provider {
	case "duckdns":
		if text != "OK" {
			return fmt.Errorf("DuckDNS отклонил обновление")
		}
	case "cloudflare":
		var result struct {
			Success bool `json:"success"`
		}
		if json.Unmarshal(body, &result) != nil || !result.Success {
			return fmt.Errorf("Cloudflare отклонил обновление")
		}
	case "noip":
		if !strings.HasPrefix(text, "good ") && !strings.HasPrefix(text, "nochg ") {
			if text == "911" {
				return &providerError{message: "No-IP временно недоступен: 911", retryAfter: noIPBackoff}
			}
			return &providerError{message: fmt.Sprintf("No-IP отклонил обновление: %s; обновления приостановлены до изменения настройки", text), suspend: true}
		}
	}
	return nil
}

func redactedProviderError(err error, cfg config.DDNS) string {
	// net/http wraps transport failures in url.Error whose Error method prints
	// the complete request URL. DuckDNS carries its token in that query string,
	// so forwarding the wrapper to status/UI and journal exposes the credential.
	var requestError *url.Error
	if errors.As(err, &requestError) && requestError.Err != nil {
		err = requestError.Err
	}
	message := err.Error()
	for _, secret := range []string{cfg.Token, cfg.Password} {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[скрыто]")
		}
	}
	return message
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("ответ превышает лимит %d байт", limit)
	}
	return body, nil
}
