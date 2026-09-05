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
	"runtime"
	"sort"
	"strconv"
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
	return s.PlanContext(context.Background(), old, next)
}

func (s *Subsystem) PlanContext(ctx context.Context, old, next *config.Config) ([]apply.Action, error) {
	var before []config.WiFiRadio
	if old != nil {
		before = enabledRadios(old)
	}
	after := enabledRadios(next)
	if reflect.DeepEqual(before, after) {
		if err := s.health(ctx, next, 1); err != nil {
			return []apply.Action{{Subsystem: s.Name(), Kind: "restart", Target: "Wi-Fi", Detail: "исправление расхождения с живыми точками доступа", Disruptive: true}}, nil
		}
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
	radios := enabledRadios(cfg)
	ownedIDs := map[string]ownedRadio{}
	for _, item := range owned {
		ownedIDs[item.ID] = item
	}
	for _, radio := range radios {
		wanted[radio.ID] = radio
		if _, err := RenderRadio(radio, cfg); err != nil {
			return fmt.Errorf("радио %s: %w", radio.Device, err)
		}
		confPath, unitPath := s.paths(radio)
		if previous, ok := ownedIDs[radio.ID]; ok {
			if previous.Unit != unitName(radio) {
				return fmt.Errorf("радио %s имеет противоречивый ownership unit %s", radio.ID, previous.Unit)
			}
		} else if pathExists(confPath) || pathExists(unitPath) {
			return fmt.Errorf("артефакты радио %s уже существуют и не принадлежат netOS", radio.ID)
		}
	}
	for _, item := range owned {
		if _, ok := wanted[item.ID]; !ok {
			if err := s.remove(ctx, item); err != nil {
				return fmt.Errorf("удаление Wi-Fi %s: %w", item.ID, err)
			}
		}
	}
	next := make([]ownedRadio, 0, len(wanted))
	for _, radio := range radios {
		if err := s.applyRadio(ctx, cfg, radio); err != nil {
			if _, existed := ownedIDs[radio.ID]; !existed {
				item := ownedRadio{ID: radio.ID, Unit: unitName(radio)}
				if cleanupErr := s.remove(ctx, item); cleanupErr != nil {
					recovery := append(append([]ownedRadio(nil), owned...), item)
					stateErr := s.writeOwned(recovery)
					return fmt.Errorf("радио %s: %w; уборка нового объекта: %v; сохранение ownership: %v", radio.Device, err, cleanupErr, stateErr)
				}
			}
			return fmt.Errorf("радио %s: %w", radio.Device, err)
		}
		next = append(next, ownedRadio{ID: radio.ID, Unit: unitName(radio)})
	}
	if sameOwnedRadios(owned, next) {
		return nil
	}
	if err := s.writeOwned(next); err != nil {
		var cleanupErrs []string
		for _, item := range next {
			if _, existed := ownedIDs[item.ID]; !existed {
				if cleanupErr := s.remove(ctx, item); cleanupErr != nil {
					cleanupErrs = append(cleanupErrs, cleanupErr.Error())
				}
			}
		}
		if len(cleanupErrs) > 0 {
			return fmt.Errorf("%w; уборка после отказа записи ownership: %s", err, strings.Join(cleanupErrs, "; "))
		}
		return err
	}
	return nil
}

func (s *Subsystem) applyRadio(ctx context.Context, cfg *config.Config, radio config.WiFiRadio) error {
	confPath, unitPath := s.paths(radio)
	conf, err := RenderRadio(radio, cfg)
	if err != nil {
		return err
	}
	unit := []byte(renderUnit(radio, confPath))
	confReady := wifiFileReady(confPath, conf, 0o600)
	unitReady := wifiFileReady(unitPath, unit, 0o644)
	changed := !confReady || !unitReady
	if !confReady {
		if err := system.WriteFileAtomic(confPath, conf, 0o600); err != nil {
			return err
		}
	}
	if !unitReady {
		if err := system.WriteFileAtomic(unitPath, unit, 0o644); err != nil {
			return err
		}
	}
	apReady, info := s.radioRuntimeMatches(ctx, cfg, radio)
	switch {
	case radio.TxPower > 0 && !txPowerMatches(info, radio.TxPower):
		if _, err := s.Runner.Run(ctx, "iw", "dev", radio.Device, "set", "txpower", "fixed", fmt.Sprint(radio.TxPower*100)); err != nil {
			return fmt.Errorf("мощность передатчика: %w", err)
		}
	case radio.TxPower == 0:
		// Ноль означает «как решит драйвер», и вернуть это состояние обязаны
		// мы: раньше значение просто не трогали, и после отката конфигурации
		// радио оставалось на мощности, которую администратор уже отменил.
		//
		// Отказ драйвера вернуться в автоматический режим не повод откатывать
		// всю конфигурацию: мощность — не связность, а команда идемпотентна и
		// повторится при следующем применении.
		_, _ = s.Runner.Run(ctx, "iw", "dev", radio.Device, "set", "txpower", "auto")
	}
	if changed {
		if _, err := s.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	name := unitName(radio)
	enabled, _ := s.Runner.Run(ctx, "systemctl", "is-enabled", name)
	if strings.TrimSpace(enabled) != "enabled" {
		if _, err := s.Runner.Run(ctx, "systemctl", "enable", name); err != nil {
			return err
		}
	}
	active, _ := s.Runner.Run(ctx, "systemctl", "is-active", name)
	if changed || strings.TrimSpace(active) != "active" || !apReady {
		if _, err := s.Runner.Run(ctx, "systemctl", "restart", name); err != nil {
			return fmt.Errorf("запуск hostapd: %w", err)
		}
	}
	return nil
}

func (s *Subsystem) Health(ctx context.Context, cfg *config.Config) error {
	return s.health(ctx, cfg, 60)
}

func (s *Subsystem) health(ctx context.Context, cfg *config.Config, attempts int) error {
	radios := enabledRadios(cfg)
	owned, err := s.readOwned()
	if err != nil {
		return err
	}
	expectedOwned := make([]ownedRadio, 0, len(radios))
	for _, radio := range radios {
		expectedOwned = append(expectedOwned, ownedRadio{ID: radio.ID, Unit: unitName(radio)})
	}
	if !sameOwnedRadios(owned, expectedOwned) {
		return fmt.Errorf("список принадлежащих netOS Wi-Fi units не соответствует конфигурации")
	}
	for _, radio := range radios {
		confPath, unitPath := s.paths(radio)
		conf, err := RenderRadio(radio, cfg)
		if err != nil {
			return err
		}
		unit := []byte(renderUnit(radio, confPath))
		if !wifiFileReady(confPath, conf, 0o600) || !wifiFileReady(unitPath, unit, 0o644) {
			return fmt.Errorf("артефакты hostapd для %s не соответствуют конфигурации", radio.Device)
		}
		enabled, err := s.Runner.Run(ctx, "systemctl", "is-enabled", unitName(radio))
		if err != nil || strings.TrimSpace(enabled) != "enabled" {
			return fmt.Errorf("unit hostapd для %s не включён", radio.Device)
		}
		ready := false
		for attempt := 0; attempt < attempts; attempt++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			active, _ := s.Runner.Run(ctx, "systemctl", "is-active", unitName(radio))
			allReady, primaryInfo := s.radioRuntimeMatches(ctx, cfg, radio)
			allReady = strings.TrimSpace(active) == "active" && allReady && (radio.TxPower == 0 || txPowerMatches(primaryInfo, radio.TxPower))
			if allReady {
				ready = true
				break
			}
			if attempt+1 == attempts {
				break
			}
			timer := time.NewTimer(150 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		if !ready {
			return fmt.Errorf("hostapd не поднял все Wi-Fi-сети на %s", radio.Device)
		}
	}
	return nil
}

func (s *Subsystem) remove(ctx context.Context, item ownedRadio) error {
	for _, action := range []string{"stop", "disable"} {
		if _, err := s.Runner.Run(ctx, "systemctl", action, item.Unit); err != nil && !missingWiFiObject(err) {
			return err
		}
	}
	token := radioToken(item.ID)
	for _, path := range []string{filepath.Join(s.StateDir, "hostapd-"+token+".conf"), filepath.Join(s.UnitDir, item.Unit)} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if _, err := s.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if active, _ := s.Runner.Run(ctx, "systemctl", "is-active", item.Unit); strings.TrimSpace(active) == "active" {
		return fmt.Errorf("unit %s остался активным", item.Unit)
	}
	if pathExists(filepath.Join(s.StateDir, "hostapd-"+token+".conf")) || pathExists(filepath.Join(s.UnitDir, item.Unit)) {
		return fmt.Errorf("артефакты %s остались после удаления", item.Unit)
	}
	return nil
}

func sameOwnedRadios(left, right []ownedRadio) bool {
	key := func(items []ownedRadio) []string {
		out := make([]string, 0, len(items))
		for _, item := range items {
			out = append(out, item.ID+"\x00"+item.Unit)
		}
		sort.Strings(out)
		return out
	}
	return reflect.DeepEqual(key(left), key(right))
}

func wifiFileReady(path string, expected []byte, mode os.FileMode) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm() != mode) {
		return false
	}
	data, err := os.ReadFile(path)
	return err == nil && string(data) == string(expected)
}

func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func (s *Subsystem) radioRuntimeMatches(ctx context.Context, cfg *config.Config, radio config.WiFiRadio) (bool, string) {
	allReady := true
	primaryInfo := ""
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
		if bssIndex == 0 {
			primaryInfo = info
		}
		if err != nil || !radioInfoMatches(info, device, radio.Channel, ssid.SSID) {
			allReady = false
		}
		// Точка доступа без моста — это работающая сеть без сегмента:
		// клиент подключается к SSID, но не видит ни шлюза, ни соседей.
		// Проверять состояние радио и не проверять мост означало считать
		// такую сеть исправной, а её надо поднимать заново.
		if bridge := bridgeFor(cfg, ssid); bridge != "" && linkExists(device) && masterOf(device) != bridge {
			allReady = false
		}
		bssIndex++
	}
	return allReady && bssIndex > 0, primaryInfo
}

// bridgeFor — интерфейс сегмента, в который hostapd обязан включить сеть.
func bridgeFor(cfg *config.Config, ssid config.WiFiSSID) string {
	if cfg == nil {
		return ""
	}
	for _, network := range cfg.Networks {
		if network.ID == ssid.Network {
			if !network.Enabled {
				return ""
			}
			return cfg.InterfaceName(network.Interface)
		}
	}
	return ""
}

// linkExists сообщает, есть ли устройство в системе. Проверять членство в
// мосте имеет смысл только для настоящего радио: на машине без него (сборка,
// тесты) отсутствие устройства не значит, что сеть собрана неправильно.
func linkExists(name string) bool {
	_, err := os.Stat(filepath.Join("/sys/class/net", name))
	return err == nil
}

// masterOf возвращает мост или агрегацию, которой подчинён интерфейс.
func masterOf(name string) string {
	target, err := os.Readlink(filepath.Join("/sys/class/net", name, "master"))
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

func radioInfoMatches(info, device string, channel int, ssid string) bool {
	var gotDevice, gotType, gotSSID string
	gotChannel := -1
	for _, raw := range strings.Split(strings.ReplaceAll(info, "\r\n", "\n"), "\n") {
		line := strings.TrimLeft(raw, " \t")
		switch {
		case strings.HasPrefix(line, "Interface "):
			gotDevice = strings.TrimSpace(strings.TrimPrefix(line, "Interface "))
		case strings.HasPrefix(line, "type "):
			gotType = strings.TrimSpace(strings.TrimPrefix(line, "type "))
		case strings.HasPrefix(line, "ssid "):
			gotSSID = strings.TrimSuffix(strings.TrimPrefix(line, "ssid "), "\r")
		case strings.HasPrefix(line, "channel "):
			fields := strings.Fields(strings.TrimPrefix(line, "channel "))
			if len(fields) > 0 {
				gotChannel, _ = strconv.Atoi(fields[0])
			}
		}
	}
	return gotDevice == device && gotType == "AP" && gotChannel == channel && gotSSID == ssid
}

func txPowerMatches(info string, wanted int) bool {
	for _, raw := range strings.Split(info, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "txpower ") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "txpower "))
		if len(fields) > 0 {
			value, err := strconv.ParseFloat(fields[0], 64)
			return err == nil && value == float64(wanted)
		}
	}
	return false
}

func missingWiFiObject(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "not found") || strings.Contains(text, "not loaded") || strings.Contains(text, "no such")
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
