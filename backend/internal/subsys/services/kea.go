package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

const (
	keaConfPath = "/var/lib/netos/generated/kea-dhcp4.json"
	// Debian's Kea AppArmor profile only allows lease databases below
	// /var/lib/kea. A syntactically valid config outside it starts and then
	// immediately dies with DHCPSRV_MEMFILE_FAILED_TO_OPEN.
	keaLeasePath = "/var/lib/kea/netos-leases4.csv"
	keaUnit      = "netos-kea-dhcp4.service"
)

type KeaDHCP struct {
	Runner  system.Runner
	Systemd *system.Systemd
}

func NewKeaDHCP(r system.Runner) *KeaDHCP { return &KeaDHCP{Runner: r, Systemd: system.NewSystemd(r)} }
func (d *KeaDHCP) Needed(cfg *config.Config) bool {
	return cfg.DHCP.Enabled && cfg.DHCP.Provider == "kea"
}

func (d *KeaDHCP) Render(cfg *config.Config) string {
	byID := map[string]string{}
	for _, i := range cfg.Interfaces {
		byID[i.ID] = i.Name
	}
	ifacesSet := map[string]bool{}
	privateOptions := map[int]bool{}
	var subnets []any
	subnetID := map[string]int{}
	for _, n := range cfg.Networks {
		if !n.Enabled || !n.DHCPPool.Enabled {
			continue
		}
		prefix, err := netip.ParsePrefix(n.RouterAddress)
		if err != nil {
			continue
		}
		iface := byID[n.Interface]
		if iface == "" {
			continue
		}
		ifacesSet[iface] = true
		p := n.DHCPPool
		options := []any{}
		gateway := p.Gateway
		if gateway == "" {
			gateway = addressOf(n.RouterAddress)
		}
		options = append(options, map[string]any{"name": "routers", "data": gateway})
		dns := p.DNSServers
		if len(dns) == 0 {
			dns = []string{addressOf(n.RouterAddress)}
		}
		options = append(options, map[string]any{"name": "domain-name-servers", "data": joinComma(dns)})
		if p.Domain != "" {
			options = append(options, map[string]any{"name": "domain-name", "data": p.Domain})
		}
		codes := make([]string, 0, len(p.Options))
		for code := range p.Options {
			codes = append(codes, code)
		}
		sort.Strings(codes)
		for _, code := range codes {
			if n, err := strconv.Atoi(code); err == nil && n > 0 && n < 255 {
				if n >= 224 {
					privateOptions[n] = true
				}
				options = append(options, map[string]any{"code": n, "space": "dhcp4", "csv-format": true, "data": p.Options[code]})
			}
		}
		id := len(subnets) + 1
		subnetID[n.ID] = id
		subnets = append(subnets, map[string]any{"id": id, "subnet": prefix.Masked().String(), "interface": iface, "valid-lifetime": p.LeaseTime, "pools": []any{map[string]any{"pool": p.Start + " - " + p.End}}, "option-data": options, "reservations": []any{}})
	}
	blocked := map[string]bool{}
	for _, cl := range cfg.Clients {
		if cl.Blocked {
			blocked[strings.ToLower(cl.MAC)] = true
		}
	}
	for _, res := range cfg.DHCP.Reservations {
		if !res.Enabled {
			continue
		}
		if blocked[strings.ToLower(res.MAC)] {
			continue
		}
		id := subnetID[res.Network]
		if id == 0 {
			continue
		}
		s := subnets[id-1].(map[string]any)
		r := map[string]any{"hw-address": res.MAC, "ip-address": res.IP}
		if res.Hostname != "" {
			r["hostname"] = res.Hostname
		}
		s["reservations"] = append(s["reservations"].([]any), r)
	}
	// DROP — специальный класс Kea: пакет от заблокированного MAC отбрасывается
	// после поиска reservation и адрес не выдаётся.
	globalReservations := []any{}
	for _, cl := range cfg.Clients {
		if !cl.Blocked || cl.MAC == "" {
			continue
		}
		globalReservations = append(globalReservations, map[string]any{"hw-address": cl.MAC, "client-classes": []string{"DROP"}})
	}
	ifaces := make([]string, 0, len(ifacesSet))
	for v := range ifacesSet {
		ifaces = append(ifaces, v)
	}
	sort.Strings(ifaces)
	optionDefs := []any{}
	privateCodes := make([]int, 0, len(privateOptions))
	for code := range privateOptions {
		privateCodes = append(privateCodes, code)
	}
	sort.Ints(privateCodes)
	for _, code := range privateCodes {
		optionDefs = append(optionDefs, map[string]any{"name": fmt.Sprintf("netos-option-%d", code), "code": code, "type": "string", "space": "dhcp4"})
	}
	// A newly-created bridge can need a short moment to acquire carrier from
	// its dummy port. Without retries Kea stays "active" but opens no DHCP
	// socket, so clients never receive an address until the next Apply.
	interfaces := map[string]any{
		"interfaces":                      ifaces,
		"service-sockets-max-retries":     60,
		"service-sockets-retry-wait-time": 1000,
	}
	dhcp4 := map[string]any{"interfaces-config": interfaces, "authoritative": true, "early-global-reservations-lookup": true, "reservations-global": true, "reservations": globalReservations, "lease-database": map[string]any{"type": "memfile", "persist": true, "name": keaLeasePath, "lfc-interval": 3600}, "option-def": optionDefs, "subnet4": subnets}
	root := map[string]any{"Dhcp4": dhcp4}
	data, _ := json.MarshalIndent(root, "", "  ")
	return string(data) + "\n"
}
func joinComma(v []string) string {
	out := ""
	for i, s := range v {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
func (d *KeaDHCP) Apply(ctx context.Context, cfg *config.Config) error {
	if !d.Needed(cfg) {
		return d.Systemd.Disable(ctx, keaUnit)
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(d.Render(cfg)), &root); err != nil {
		return fmt.Errorf("генерация конфигурации Kea: %w", err)
	}
	dhcp4 := root["Dhcp4"].(map[string]any)
	if len(dhcp4["subnet4"].([]any)) == 0 {
		return fmt.Errorf("Kea DHCP: нет включённых пулов на доступных интерфейсах")
	}
	content := []byte(d.Render(cfg))
	changed := system.FileChanged(keaConfPath, content)
	if err := system.WriteFileAtomic(keaConfPath, content, 0o644); err != nil {
		return err
	}
	if err := d.ensureUnit(ctx); err != nil {
		return err
	}
	if _, err := d.Runner.Run(ctx, "kea-dhcp4", "-t", keaConfPath); err != nil {
		return fmt.Errorf("проверка конфигурации Kea DHCP: %w", err)
	}
	if !changed && d.Systemd.IsActive(ctx, keaUnit) {
		return nil
	}
	return d.Systemd.Restart(ctx, keaUnit)
}
func (d *KeaDHCP) ensureUnit(ctx context.Context) error {
	unit := renderKeaUnit()
	path := filepath.Join("/etc/systemd/system", keaUnit)
	if !system.FileChanged(path, []byte(unit)) {
		return nil
	}
	if err := system.WriteFileAtomic(path, []byte(unit), 0o644); err != nil {
		return err
	}
	return d.Systemd.DaemonReload(ctx)
}

func renderKeaUnit() string {
	return "[Unit]\nDescription=netOS Kea DHCPv4\nAfter=network.target\nWants=network.target\n\n[Service]\nType=simple\nRuntimeDirectory=kea\nRuntimeDirectoryMode=0755\nExecStart=/usr/sbin/kea-dhcp4 -c " + keaConfPath + "\nRestart=always\nRestartSec=2\n\n[Install]\nWantedBy=multi-user.target\n"
}
func (d *KeaDHCP) Health(ctx context.Context, cfg *config.Config) error {
	if d.Needed(cfg) && !d.Systemd.IsActive(ctx, keaUnit) {
		return fmt.Errorf("Kea DHCP не запущен")
	}
	return nil
}
