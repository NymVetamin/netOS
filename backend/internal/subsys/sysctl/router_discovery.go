package sysctl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"golang.org/x/net/ipv6"
)

// RouterDiscovery runs after the IPv6 input/output filter is ready. networkd
// can finish link-local DAD before netOS sets accept_ra=2, missing the kernel's
// initial solicitation. A provider without IPv6 must not hold up Apply.
type RouterDiscovery struct{}

func (RouterDiscovery) Name() string                                     { return "ipv6-discovery" }
func (RouterDiscovery) Plan(_, _ *config.Config) ([]apply.Action, error) { return nil, nil }
func (RouterDiscovery) Health(context.Context, *config.Config) error     { return nil }

func (RouterDiscovery) Apply(ctx context.Context, cfg *config.Config) error {
	if cfg.IPv6.Mode != "passthrough" || len(cfg.WANs) == 0 {
		return nil
	}
	state, err := os.ReadFile("/proc/net/if_inet6")
	if err != nil {
		return err
	}
	targets := routerDiscoveryTargets(cfg, string(state))
	if len(targets) == 0 {
		return nil
	}
	socket, err := net.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return err
	}
	defer socket.Close()
	conn := ipv6.NewPacketConn(socket)
	dst := &net.IPAddr{IP: net.ParseIP("ff02::2")}
	// ICMPv6 RS has a four-byte header and four reserved bytes. Linux
	// supplies the source address and checksum for an ICMPv6 raw socket.
	message := []byte{byte(ipv6.ICMPTypeRouterSolicitation), 0, 0, 0, 0, 0, 0, 0}
	for _, index := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := conn.WriteTo(message, &ipv6.ControlMessage{HopLimit: 255, IfIndex: index}, dst)
		if err != nil && !errors.Is(err, syscall.ENETDOWN) && !errors.Is(err, syscall.ENODEV) && !errors.Is(err, syscall.ENETUNREACH) {
			return fmt.Errorf("запрос IPv6-маршрутизатора на интерфейсе %d: %w", index, err)
		}
	}
	return nil
}

func routerDiscoveryTargets(cfg *config.Config, state string) []int {
	// Linux if_inet6 columns are address, index (hex), prefix length, scope,
	// address flags and name. A global address suppresses discovery even if
	// its link-local row follows it in the snapshot.
	indexByName := map[string]int{}
	for line := range strings.SplitSeq(state, "\n") {
		f := strings.Fields(line)
		if len(f) != 6 {
			continue
		}
		flags, err := strconv.ParseUint(f[4], 16, 32)
		if err != nil || flags&0x08 != 0 { // IFA_F_DADFAILED
			continue
		}
		switch f[3] {
		case "00":
			indexByName[f[5]] = -1
		case "20":
			if indexByName[f[5]] == 0 {
				index, err := strconv.ParseUint(f[1], 16, 31)
				if err == nil {
					indexByName[f[5]] = int(index)
				}
			}
		}
	}
	names := make(map[string]string, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		if iface.Enabled {
			names[iface.ID] = iface.Name
		}
	}
	var targets []int
	for _, wan := range cfg.WANs {
		name := names[wan.Interface]
		if !wan.Enabled || name == "" {
			continue
		}
		if wan.Proto == "pppoe" || wan.Proto == "l2tp" {
			name = "ppp-" + wan.ID
		}
		if index := indexByName[name]; index > 0 {
			targets = append(targets, index)
			delete(indexByName, name)
		}
	}
	return targets
}
