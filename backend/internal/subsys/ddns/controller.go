// Package ddns updates public DNS records without exposing provider secrets on
// a process command line or in generated systemd units.
package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
)

type Logger interface {
	Infof(string, ...any)
	Warnf(string, ...any)
}

type Status struct {
	Enabled  bool      `json:"enabled"`
	LastRun  time.Time `json:"last_run,omitempty"`
	NextRun  time.Time `json:"next_run,omitempty"`
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
	Now             func() time.Time

	mu     sync.RWMutex
	status Status
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
	}
	c.ResolveAddress = c.resolveAddress
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
	c.status = Status{Enabled: cfg.DDNS.Enabled, Provider: cfg.DDNS.Provider, Hostname: cfg.DDNS.Hostname}
	return nil
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
	ticker := time.NewTicker(time.Second)
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
	c.mu.RLock()
	next := c.status.NextRun
	c.mu.RUnlock()
	if !next.IsZero() && c.Now().Before(next) {
		return
	}
	address, err := c.ResolveAddress(ctx, cfg)
	if err == nil {
		err = c.update(ctx, cfg.DDNS, address)
	}
	interval := time.Duration(cfg.DDNS.Interval) * time.Second
	if interval < time.Minute {
		interval = time.Minute
	}
	now := c.Now()
	status := Status{
		Enabled: true, LastRun: now, NextRun: now.Add(interval), Address: address,
		Success: err == nil, Provider: cfg.DDNS.Provider, Hostname: cfg.DDNS.Hostname,
	}
	if err != nil {
		status.Message = err.Error()
		if c.Logger != nil {
			c.Logger.Warnf("DDNS %s: %v", cfg.DDNS.Hostname, err)
		}
	} else if c.Logger != nil {
		c.Logger.Infof("DDNS %s обновлён: %s", cfg.DDNS.Hostname, address)
	}
	c.mu.Lock()
	c.status = status
	c.mu.Unlock()
}

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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
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
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", fmt.Errorf("интерфейс %s: %w", name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
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
		return fmt.Errorf("запрос к провайдеру: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("провайдер ответил HTTP %d", resp.StatusCode)
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
			return fmt.Errorf("No-IP отклонил обновление: %s", text)
		}
	}
	return nil
}
