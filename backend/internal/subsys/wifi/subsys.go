// Package wifi manages hostapd instances owned by netOS.
package wifi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

type ownedRadio struct {
	ID   string `json:"id"`
	Unit string `json:"unit"`
}

type Subsystem struct {
	Runner   system.Runner
	StateDir string
	UnitDir  string
}

func New(r system.Runner, stateDir string) *Subsystem {
	return &Subsystem{Runner: r, StateDir: stateDir, UnitDir: "/etc/systemd/system"}
}

func (s *Subsystem) Name() string { return "wifi" }

func enabledRadios(cfg *config.Config) []config.WiFiRadio {
	var out []config.WiFiRadio
	for _, radio := range cfg.WiFi {
		if radio.Enabled {
			out = append(out, radio)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func radioToken(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:6])
}

func unitName(radio config.WiFiRadio) string {
	return "netos-hostapd-" + radioToken(radio.ID) + ".service"
}

func (s *Subsystem) paths(radio config.WiFiRadio) (string, string) {
	token := radioToken(radio.ID)
	return filepath.Join(s.StateDir, "hostapd-"+token+".conf"), filepath.Join(s.UnitDir, "netos-hostapd-"+token+".service")
}

func (s *Subsystem) Plan(old, next *config.Config) ([]apply.Action, error) {
	var before []config.WiFiRadio
	if old != nil {
		before = enabledRadios(old)
	}
	after := enabledRadios(next)
	if reflect.DeepEqual(before, after) {
		return nil, nil
	}
	return []apply.Action{{Kind: "restart", Target: "Wi-Fi", Detail: "конфигурация точек доступа", Disruptive: true}}, nil
}

func (s *Subsystem) Apply(ctx context.Context, cfg *config.Config) error {
	owned, err := s.readOwned()
	if err != nil {
		return err
	}
	wanted := map[string]config.WiFiRadio{}
	for _, radio := range enabledRadios(cfg) {
		wanted[radio.ID] = radio
	}
	for _, item := range owned {
		if _, ok := wanted[item.ID]; !ok {
			s.remove(ctx, item)
		}
	}
	next := make([]ownedRadio, 0, len(wanted))
	for _, radio := range enabledRadios(cfg) {
		if err := s.applyRadio(ctx, cfg, radio); err != nil {
			return fmt.Errorf("радио %s: %w", radio.Device, err)
		}
		next = append(next, ownedRadio{ID: radio.ID, Unit: unitName(radio)})
	}
	return s.writeOwned(next)
}

func (s *Subsystem) applyRadio(ctx context.Context, cfg *config.Config, radio config.WiFiRadio) error {
	confPath, unitPath := s.paths(radio)
	conf, err := RenderRadio(radio, cfg)
	if err != nil {
		return err
	}
	unit := []byte(renderUnit(radio, confPath))
	changed := system.FileChanged(confPath, conf) || system.FileChanged(unitPath, unit)
	if err := system.WriteFileAtomic(confPath, conf, 0o600); err != nil {
		return err
	}
	if err := system.WriteFileAtomic(unitPath, unit, 0o644); err != nil {
		return err
	}
	if radio.TxPower > 0 {
		if _, err := s.Runner.Run(ctx, "iw", "dev", radio.Device, "set", "txpower", "fixed", fmt.Sprint(radio.TxPower*100)); err != nil {
			return fmt.Errorf("мощность передатчика: %w", err)
		}
	}
	if changed {
		if _, err := s.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	name := unitName(radio)
	if _, err := s.Runner.Run(ctx, "systemctl", "enable", name); err != nil {
		return err
	}
	active, _ := s.Runner.Run(ctx, "systemctl", "is-active", name)
	if changed || strings.TrimSpace(active) != "active" {
		if _, err := s.Runner.Run(ctx, "systemctl", "restart", name); err != nil {
			return fmt.Errorf("запуск hostapd: %w", err)
		}
	}
	return nil
}

func (s *Subsystem) Health(ctx context.Context, cfg *config.Config) error {
	for _, radio := range enabledRadios(cfg) {
		ready := false
		for attempt := 0; attempt < 60; attempt++ {
			active, _ := s.Runner.Run(ctx, "systemctl", "is-active", unitName(radio))
			allReady := strings.TrimSpace(active) == "active"
			bssIndex := 0
			for _, ssid := range radio.SSIDs {
				if !ssid.Enabled {
					continue
				}
				device := radio.Device
				if bssIndex > 0 {
					device = fmt.Sprintf("%s-n%d", radio.Device, bssIndex)
				}
				info, err := s.Runner.Run(ctx, "iw", "dev", device, "info")
				if err != nil || !strings.Contains(info, "type AP") ||
					!strings.Contains(info, fmt.Sprintf("channel %d", radio.Channel)) ||
					!strings.Contains(info, "ssid "+ssid.SSID) {
					allReady = false
				}
				bssIndex++
			}
			if allReady {
				ready = true
				break
			}
			time.Sleep(150 * time.Millisecond)
		}
		if !ready {
			return fmt.Errorf("hostapd не поднял все Wi-Fi-сети на %s", radio.Device)
		}
	}
	return nil
}

func (s *Subsystem) remove(ctx context.Context, item ownedRadio) {
	_, _ = s.Runner.Run(ctx, "systemctl", "disable", item.Unit)
	_, _ = s.Runner.Run(ctx, "systemctl", "stop", item.Unit)
	token := radioToken(item.ID)
	_ = os.Remove(filepath.Join(s.StateDir, "hostapd-"+token+".conf"))
	_ = os.Remove(filepath.Join(s.UnitDir, item.Unit))
	_, _ = s.Runner.Run(ctx, "systemctl", "daemon-reload")
}

func (s *Subsystem) ownedPath() string { return filepath.Join(s.StateDir, "owned-wifi.json") }

func (s *Subsystem) readOwned() ([]ownedRadio, error) {
	data, err := os.ReadFile(s.ownedPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []ownedRadio
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("разбор списка Wi-Fi: %w", err)
	}
	return out, nil
}

func (s *Subsystem) writeOwned(items []ownedRadio) error {
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	return system.WriteFileAtomic(s.ownedPath(), append(data, '\n'), 0o600)
}
