package vpnservers

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/netos-router/netos/internal/config"
)

const L2TPIPsecGuardChain = "NETOS-L2TP-IPSEC"

// RenderIPsec exposes the complete configuration of the shared server daemon.
func RenderIPsec(cfg *config.Config) ([]byte, error) {
	return renderIPsecServers(ikev2Servers(cfg), cfg, l2tpIPsecServers(cfg))
}

// L2TPIPsecGuard returns the same transport boundary used by the firewall
// renderer and by xl2tpd's pre-start check. It must exist before opening UDP1701.
func L2TPIPsecGuard(server config.VPNServer) (match string, rules []string) {
	c, _ := server.L2TPConfig()
	match = "-m addrtype --dst-type LOCAL -p udp --dport 1701"
	if c.Listen != "0.0.0.0" {
		match = "-d " + c.Listen + " -p udp --dport 1701"
	}
	rules = []string{
		"-A " + L2TPIPsecGuardChain + " -m policy --dir in --pol ipsec --proto esp -j RETURN",
		"-A " + L2TPIPsecGuardChain + " -j DROP",
	}
	return
}

func renderL2TPIPsecGuard(server config.VPNServer) []byte {
	match, rules := L2TPIPsecGuard(server)
	// Values are validated numeric addresses and fixed tokens, never usernames
	// or PSKs. --noflush preserves unrelated tables/chains; the transaction only
	// replaces our chain and installs a missing jump without accumulating copies.
	return []byte(fmt.Sprintf(`#!/bin/sh
set -eu
attached=no
iptables -w -t mangle -C PREROUTING %s -j %s 2>/dev/null && attached=yes
{
    printf '%%s\n' '*mangle' ':%s - [0:0]' '-F %s'
    if [ "$attached" = no ]; then
        printf '%%s\n' '-I PREROUTING 1 %s -j %s'
    fi
    printf '%%s\n' '%s' 'COMMIT'
} | iptables-restore -w --noflush
`, match, L2TPIPsecGuardChain, L2TPIPsecGuardChain, L2TPIPsecGuardChain, match, L2TPIPsecGuardChain, strings.Join(rules, "' '")))
}

func (s *Subsystem) healthIPsec(ctx context.Context, cfg *config.Config) error {
	if err := s.unitActiveEnabled(ctx, ikev2Unit); err != nil {
		return fmt.Errorf("сервер IPsec не работает: %w", err)
	}
	ike, l2tp := ikev2Servers(cfg), l2tpIPsecServers(cfg)
	conf, err := renderIPsecServers(ike, cfg, l2tp)
	if err != nil {
		return err
	}
	paths := s.ikev2Paths()
	secret := ""
	if len(ike) > 0 {
		secret, err = readIKEv2AuthSecret(paths.root)
		if err != nil {
			return err
		}
	}
	for _, file := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{paths.conf, conf, 0o600},
		{paths.daemonConf, renderIKEv2DaemonConfig(secret), 0o600},
		{paths.unit, renderIPsecUnit(paths.conf, paths.daemonConf, len(ike) > 0), 0o644},
	} {
		if err := healthyFile(file.path, file.data, file.mode); err != nil {
			return err
		}
	}
	return nil
}

func l2tpIPsecServers(cfg *config.Config) []config.VPNServer {
	var out []config.VPNServer
	for _, server := range cfg.VPNServers {
		if server.Enabled && server.UsesL2TPIPsec() {
			out = append(out, server)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

func renderL2TPIPsecConnection(b *strings.Builder, server config.VPNServer) {
	c, _ := server.L2TPConfig()
	fmt.Fprintf(b, `  netos-l2tp-srv%d {
    version = 1
    local_addrs = %s
    unique = never
    proposals = aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp1024,3des-sha1-modp1024
    fragmentation = yes
    dpd_delay = 30s
    local {
      auth = psk
    }
    remote {
      auth = psk
    }
    children {
      netos-l2tp-srv%d {
        mode = transport
        local_ts = dynamic[udp/1701]
        remote_ts = dynamic[udp]
        esp_proposals = aes256-sha256,aes256-sha1,aes128-sha1,3des-sha1
        dpd_action = clear
      }
    }
  }
`, server.Index, c.Listen, server.Index)
}

func renderL2TPIPsecSecrets(b *strings.Builder, servers []config.VPNServer) {
	if len(servers) == 0 {
		return
	}
	fmt.Fprintln(b, "secrets {")
	for _, server := range servers {
		c, _ := server.L2TPConfig()
		// UDP1701 listener validation allows only one active L2TP server. There is
		// one shared PSK; PPP authenticates individual users inside that transport.
		fmt.Fprintf(b, "  ike-netos-l2tp-srv%d {\n    secret = 0s%s\n  }\n", server.Index, base64.StdEncoding.EncodeToString([]byte(c.PresharedKey)))
	}
	fmt.Fprintln(b, "}")
}
