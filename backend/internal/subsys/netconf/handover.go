package netconf

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// During networkd -> netos, networkd removes its static LAN address before
// netOS can add it back. Keep a local copy of the router address and a route
// to the clients while networkd releases the link.
type handoverAddress struct {
	iface, address, prefix, subnet, spare string
	metric                                string
	loopAdded                             bool
}

type addressHandover struct {
	s     *Subsystem
	items []handoverAddress
}

type kernelLink struct {
	AddrInfo []struct {
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
	} `json:"addr_info"`
}

func (s *Subsystem) ipv4Addresses(ctx context.Context, iface string) ([]kernelLink, error) {
	args := []string{"-j", "-4", "address", "show"}
	if iface != "" {
		args = append(args, "dev", iface)
	}
	out, err := s.Runner.Run(ctx, "ip", args...)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(out) == "" {
		return nil, fmt.Errorf("ip did not return IPv4 address data for %s", iface)
	}
	var links []kernelLink
	if err := json.Unmarshal([]byte(out), &links); err != nil {
		return nil, fmt.Errorf("адреса ядра: %w", err)
	}
	return links, nil
}

func containsIPv4(links []kernelLink, address string, bits int) bool {
	for _, link := range links {
		for _, item := range link.AddrInfo {
			if item.Local == address && item.PrefixLen == bits {
				return true
			}
		}
	}
	return false
}

func (s *Subsystem) networkdFilesNeedSync(files map[string]string) (bool, error) {
	existing, err := filepath.Glob(filepath.Join(networkdDir, networkdPrefix+"*"))
	if err != nil {
		return false, err
	}
	for _, path := range existing {
		if _, keep := files[filepath.Base(path)]; !keep {
			return true, nil
		}
	}
	for name, content := range files {
		if system.FileChanged(filepath.Join(networkdDir, name), []byte(content)) {
			return true, nil
		}
	}
	return false, nil
}

func (s *Subsystem) protectLANAddresses(ctx context.Context, cfg *config.Config) (_ *addressHandover, retErr error) {
	guard := &addressHandover{s: s}
	defer func() {
		if retErr != nil {
			_ = ensureHandoverCleanup(guard)
		}
	}()
	interfaces := map[string]string{}
	for _, iface := range cfg.Interfaces {
		interfaces[iface.ID] = iface.Name
	}
	all, err := s.ipv4Addresses(ctx, "")
	if err != nil {
		return nil, err
	}
	loopback, err := s.ipv4Addresses(ctx, "lo")
	if err != nil {
		return nil, err
	}
	loopUsed := map[string]bool{}
	for _, link := range loopback {
		for _, address := range link.AddrInfo {
			if address.PrefixLen == 32 {
				loopUsed[address.Local] = true
			}
		}
	}
	used := map[string]bool{}
	for _, link := range all {
		for _, address := range link.AddrInfo {
			used[address.Local] = true
		}
	}
	for _, network := range cfg.Networks {
		if !network.Enabled {
			continue
		}
		iface := interfaces[network.Interface]
		prefix, err := netip.ParsePrefix(network.RouterAddress)
		if err != nil || !prefix.Addr().Is4() || iface == "" {
			continue
		}
		links, err := s.ipv4Addresses(ctx, iface)
		if err != nil {
			if strings.Contains(err.Error(), "does not exist") || strings.Contains(err.Error(), "Cannot find device") {
				continue // a newly declared bridge or VLAN is created later by netiface
			}
			return nil, err
		}
		address := prefix.Addr().String()
		if !containsIPv4(links, address, prefix.Bits()) {
			continue // newly added segment: there is no old address to protect
		}
		spare := ""
		for suffix := 254; suffix >= 1; suffix-- {
			candidate := fmt.Sprintf("198.19.255.%d", suffix)
			if !used[candidate] {
				spare = candidate
				used[candidate] = true
				break
			}
		}
		if spare == "" {
			return nil, fmt.Errorf("нет свободного временного адреса для передачи %s", address)
		}
		item := handoverAddress{iface: iface, address: address, prefix: prefix.String(), subnet: prefix.Masked().String(), spare: spare, metric: fmt.Sprint(32760 + len(guard.items))}
		if _, err := s.Runner.Run(ctx, "ip", "address", "add", spare+"/32", "dev", iface); err != nil {
			return nil, fmt.Errorf("временный адрес %s: %w", iface, err)
		}
		guard.items = append(guard.items, item)
		index := len(guard.items) - 1
		if !loopUsed[address] {
			if _, err := s.Runner.Run(ctx, "ip", "address", "add", address+"/32", "dev", "lo"); err != nil {
				return nil, fmt.Errorf("временный локальный адрес %s: %w", address, err)
			}
			guard.items[index].loopAdded = true
			loopUsed[address] = true
		}
		if _, err := s.Runner.Run(ctx, "ip", "route", "add", item.subnet, "dev", iface, "src", address, "proto", "203", "metric", item.metric); err != nil {
			return nil, fmt.Errorf("временный маршрут %s: %w", item.subnet, err)
		}
	}
	return guard, nil
}

func (g *addressHandover) waitPassive(ctx context.Context) error {
	for _, item := range g.items {
		deadline := time.Now().Add(5 * time.Second)
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			out, err := g.s.Runner.Run(ctx, "networkctl", "status", item.iface, "--no-pager")
			if err == nil && strings.Contains(out, "05-netos-"+item.iface+".network") && strings.Contains(out, "(configured)") {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("networkd не завершил передачу %s", item.iface)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	return nil
}

func (g *addressHandover) close(ctx context.Context) error {
	if g == nil {
		return nil
	}
	var failures []string
	for i := len(g.items) - 1; i >= 0; i-- {
		item := g.items[i]
		links, err := g.s.ipv4Addresses(ctx, item.iface)
		prefix, _ := netip.ParsePrefix(item.prefix)
		if err == nil && !containsIPv4(links, item.address, prefix.Bits()) {
			_, err = g.s.Runner.Run(ctx, "ip", "address", "add", item.prefix, "dev", item.iface)
		}
		if err != nil {
			failures = append(failures, item.iface+": "+err.Error())
			continue // keep the guard if the real address could not be restored
		}
		_, _ = g.s.Runner.Run(ctx, "ip", "route", "del", item.subnet, "dev", item.iface, "proto", "203", "metric", item.metric)
		if item.loopAdded {
			if _, err := g.s.Runner.Run(ctx, "ip", "address", "del", item.address+"/32", "dev", "lo"); err != nil {
				failures = append(failures, item.address+": "+err.Error())
			}
		}
		if _, err := g.s.Runner.Run(ctx, "ip", "address", "del", item.spare+"/32", "dev", item.iface); err != nil {
			failures = append(failures, item.spare+": "+err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("очистка временных адресов: %s", strings.Join(failures, "; "))
	}
	return nil
}

func ensureHandoverCleanup(g *addressHandover) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return g.close(ctx)
}
