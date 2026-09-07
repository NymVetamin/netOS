package manage

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// A factory bootstrap discovers the uplink from the live default route. Keep
// that physical IPv4 uplink reachable while deleting the old configuration;
// otherwise its now-addressless port is mistaken for the factory LAN.
type resetUplink struct {
	device, address string
	route           []string
}

func (m *Manager) captureResetUplink(ctx context.Context) (resetUplink, error) {
	var keep resetUplink
	out, err := m.Output(ctx, "ip", "-4", "route", "show", "default")
	if err != nil {
		return keep, fmt.Errorf("чтение аплинка перед сбросом: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "default" {
			continue
		}
		var device, gateway, metric string
		onlink := false
		for i, field := range fields {
			if field == "onlink" {
				onlink = true
			}
			if i+1 >= len(fields) {
				continue
			}
			switch field {
			case "dev":
				device = fields[i+1]
			case "via":
				gateway = fields[i+1]
			case "metric":
				metric = fields[i+1]
			}
		}
		if !validLinkName(device) {
			continue
		}
		if _, err := os.Stat(m.sys("/sys/class/net/" + device + "/device")); err != nil {
			continue
		}
		gw, err := netip.ParseAddr(gateway)
		if err != nil || !gw.Is4() {
			continue
		}
		if metric != "" {
			if _, err := strconv.ParseUint(metric, 10, 32); err != nil {
				continue
			}
		}
		addresses, err := m.Output(ctx, "ip", "-o", "-4", "addr", "show", "dev", device)
		if err != nil {
			return keep, fmt.Errorf("чтение адреса аплинка перед сбросом: %w", err)
		}
		for _, addressLine := range strings.Split(addresses, "\n") {
			parts := strings.Fields(addressLine)
			for i, part := range parts {
				if part != "inet" || i+1 >= len(parts) {
					continue
				}
				prefix, err := netip.ParsePrefix(parts[i+1])
				if err != nil || !prefix.Addr().Is4() {
					continue
				}
				keep.device, keep.address = device, prefix.String()
				keep.route = []string{"-4", "route", "replace", "default", "via", gw.String(), "dev", device, "proto", "boot"}
				if metric != "" {
					keep.route = append(keep.route, "metric", metric)
				}
				if onlink {
					keep.route = append(keep.route, "onlink")
				}
				return keep, nil
			}
		}
	}
	return keep, nil
}
