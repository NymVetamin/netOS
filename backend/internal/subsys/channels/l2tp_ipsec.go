package channels

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/netos-router/netos/internal/config"
)

func l2tpIPsecName(ch config.Channel) string { return fmt.Sprintf("netos-l2tp-ipsec-ch%d", ch.Index) }
func l2tpIPsecVICI(ch config.Channel) string {
	return "unix:///run/" + l2tpIPsecName(ch) + "/charon.vici"
}
func (s *Subsystem) l2tpIPsecPaths(ch config.Channel) (conf, daemon, unit string) {
	base := filepath.Join(s.StateDir, l2tpIPsecName(ch))
	return base + ".conf", base + "-daemon.conf", filepath.Join(s.UnitDir, l2tpIPsecName(ch)+".service")
}

// Guard the channel's reserved UDP port even while the daemon or SA is absent.
// The firewall renderer installs these same rules when replacing the mangle table.
func L2TPChannelIPsecRules(ch config.Channel) []string {
	port := 20000 + ch.Index
	return []string{
		fmt.Sprintf("-A OUTPUT -p udp --sport %d -m policy --dir out --pol none -j DROP", port),
		fmt.Sprintf("-A PREROUTING -m addrtype --dst-type LOCAL -p udp --dport %d -m policy --dir in --pol none -j DROP", port),
	}
}
func (s *Subsystem) l2tpIPsecGuard(ctx context.Context, ch config.Channel, enabled bool) error {
	for _, rule := range L2TPChannelIPsecRules(ch) {
		args := strings.Fields(rule)
		check := append([]string{"-w", "-t", "mangle", "-C"}, args[1:]...)
		_, err := s.Runner.Run(ctx, "iptables", check...)
		if enabled && err != nil {
			insert := append([]string{"-w", "-t", "mangle", "-I", args[1], "1"}, args[2:]...)
			if _, err := s.Runner.Run(ctx, "iptables", insert...); err != nil {
				return err
			}
		} else if !enabled && err == nil {
			remove := append([]string{"-w", "-t", "mangle", "-D"}, args[1:]...)
			if _, err := s.Runner.Run(ctx, "iptables", remove...); err != nil {
				return err
			}
		}
	}
	return nil
}
func renderL2TPIPsec(ch config.Channel, c config.L2TPChannelConfig) []byte {
	return []byte(fmt.Sprintf(`connections {
  netos-l2tp-ch%d {
    version = 1
    remote_addrs = %s
    local_addrs = %%any
    proposals = aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp1024,3des-sha1-modp1024
    encap = yes
    fragmentation = yes
    dpd_delay = 20s
    local { auth = psk }
    remote { auth = psk }
    children {
      netos-l2tp-ch%d {
        mode = transport
        reqid = %d
        local_ts = dynamic[udp/%d]
        remote_ts = dynamic[udp/1701]
        esp_proposals = aes256-sha256,aes256-sha1,aes128-sha1,3des-sha1
        start_action = trap|start
        dpd_action = restart
        close_action = start
      }
    }
  }
}
secrets {
  ike-l2tp { secret = 0s%s }
}
`, ch.Index, c.Server, ch.Index, 70000+ch.Index, 20000+ch.Index, base64.StdEncoding.EncodeToString([]byte(c.PresharedKey))))
}
func renderL2TPIPsecDaemon(ch config.Channel) []byte {
	return []byte(fmt.Sprintf(`charon {
  port = 0
  port_nat_t = 0
  load_modular = yes
  plugins {
    include /etc/strongswan.d/charon/*.conf
    vici { socket = %s }
    kernel-netlink { install_routes = no }
  }
}
include /etc/strongswan.d/*.conf
`, l2tpIPsecVICI(ch)))
}
func renderL2TPIPsecUnit(ch config.Channel, conf, daemon string) []byte {
	return []byte(fmt.Sprintf(`[Unit]
Description=netOS: L2TP IPsec channel %d
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
Environment=STRONGSWAN_CONF=%s
ExecStart=/usr/sbin/charon-systemd
ExecStartPost=/usr/sbin/swanctl --load-all --uri %s --file %s --noprompt
ExecStopPost=/usr/sbin/ip xfrm state deleteall reqid %d
ExecStopPost=/usr/sbin/ip xfrm policy deleteall dir out proto udp sport %d dport 1701
ExecStopPost=/usr/sbin/ip xfrm policy deleteall dir in proto udp sport 1701 dport %d
Restart=always
RestartSec=5
RuntimeDirectory=%s
RuntimeDirectoryMode=0700
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
`, ch.Index, daemon, l2tpIPsecVICI(ch), conf, 70000+ch.Index, 20000+ch.Index, 20000+ch.Index, l2tpIPsecName(ch)))
}
func (s *Subsystem) stopL2TPIPsec(ctx context.Context, ch config.Channel) {
	_, _ = s.Runner.Run(ctx, "systemctl", "stop", l2tpIPsecName(ch)+".service")
	_, _ = s.Runner.Run(ctx, "systemctl", "reset-failed", l2tpIPsecName(ch)+".service")
	conf, daemon, unit := s.l2tpIPsecPaths(ch)
	for _, p := range []string{conf, daemon, unit, s.l2tpIPsecGuardPath(ch)} {
		_ = os.Remove(p)
	}
}

func (s *Subsystem) l2tpIPsecGuardPath(ch config.Channel) string {
	return filepath.Join(s.StateDir, l2tpIPsecName(ch)+"-guard.sh")
}
func renderL2TPIPsecGuard(ch config.Channel) []byte {
	var b strings.Builder
	b.WriteString("#!/bin/sh\nset -eu\n")
	for _, rule := range L2TPChannelIPsecRules(ch) {
		args := strings.Fields(rule)
		fmt.Fprintf(&b, "iptables -w -t mangle -C %s 2>/dev/null || iptables -w -t mangle -I %s 1 %s\n", strings.Join(args[1:], " "), args[1], strings.Join(args[2:], " "))
	}
	return []byte(b.String())
}
func (s *Subsystem) healthL2TPIPsec(ctx context.Context, ch config.Channel, c config.L2TPChannelConfig) error {
	if !c.IPsec {
		return nil
	}
	conf, daemon, unit := s.l2tpIPsecPaths(ch)
	for _, f := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{conf, renderL2TPIPsec(ch, c), 0600}, {daemon, renderL2TPIPsecDaemon(ch), 0600}, {unit, renderL2TPIPsecUnit(ch, conf, daemon), 0644}, {s.l2tpIPsecGuardPath(ch), renderL2TPIPsecGuard(ch), 0700},
	} {
		if err := healthyChannelFile(f.path, f.data, f.mode); err != nil {
			return err
		}
	}
	for _, rule := range L2TPChannelIPsecRules(ch) {
		args := append([]string{"-w", "-t", "mangle", "-C"}, strings.Fields(rule)[1:]...)
		if _, err := s.Runner.Run(ctx, "iptables", args...); err != nil {
			return fmt.Errorf("L2TP IPsec guard: %w", err)
		}
	}
	sa, err := s.Runner.Run(ctx, "/usr/sbin/swanctl", "--list-sas", "--uri", l2tpIPsecVICI(ch))
	if err != nil || !strings.Contains(sa, "INSTALLED") {
		return fmt.Errorf("L2TP IPsec SA unavailable: %v", err)
	}
	return nil
}
