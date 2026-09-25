package channels

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

func ikev2UnitName(ch config.Channel) string {
	return fmt.Sprintf("netos-ikev2-ch%d.service", ch.Index)
}
func ikev2RuntimeName(ch config.Channel) string { return fmt.Sprintf("netos-ikev2-ch%d", ch.Index) }
func ikev2XFRMID(ch config.Channel) int         { return 60000 + ch.Index }

type ikev2ClientPaths struct{ root, conf, daemon, ca, unit string }

func (s *Subsystem) ikev2Paths(ch config.Channel) ikev2ClientPaths {
	root := filepath.Join(s.StateDir, ikev2RuntimeName(ch))
	return ikev2ClientPaths{root: root, conf: filepath.Join(root, "swanctl.conf"),
		daemon: filepath.Join(root, "strongswan.conf"), ca: filepath.Join(root, "x509ca", "ca.crt"),
		unit: filepath.Join(s.UnitDir, ikev2UnitName(ch))}
}

func ikev2ClientVICI(ch config.Channel) string {
	return "unix:///run/" + ikev2RuntimeName(ch) + "/charon.vici"
}

func renderIKEv2Client(ch config.Channel, ike config.IKEv2ChannelConfig) []byte {
	password := base64.StdEncoding.EncodeToString([]byte(ike.Password))
	return []byte(fmt.Sprintf(`connections {
  netos-ch%d {
    version = 2
    remote_addrs = %s
    local_addrs = %%any
    vips = 0.0.0.0
    fragmentation = yes
    encap = yes
    mobike = no
    dpd_delay = 20s
    local {
      auth = eap-mschapv2
      id = %s
      eap_id = %s
    }
    remote {
      auth = pubkey
      id = %s
    }
    children {
      netos-ch%d {
        local_ts = 0.0.0.0/0
        remote_ts = 0.0.0.0/0
        if_id_in = %d
        if_id_out = %d
        dpd_action = start
        close_action = start
      }
    }
  }
}
secrets {
  eap-netos-ch%d {
    id = %s
    secret = 0s%s
  }
}
`, ch.Index, ike.Server, ike.Username, ike.Username, ike.ServerIdentity,
		ch.Index, ikev2XFRMID(ch), ikev2XFRMID(ch), ch.Index, ike.Username, password))
}

func renderIKEv2ClientDaemon(ch config.Channel) []byte {
	return []byte(fmt.Sprintf(`charon {
  port = 0
  port_nat_t = 0
  install_virtual_ip_on = %s
  load_modular = yes
  plugins {
    include /etc/strongswan.d/charon/*.conf
    vici {
      socket = %s
    }
    kernel-netlink {
      install_routes = no
      install_routes_xfrmi = no
    }
  }
}
include /etc/strongswan.d/*.conf
`, InterfaceName(ch), ikev2ClientVICI(ch)))
}

func renderIKEv2ClientUnit(ch config.Channel, p ikev2ClientPaths) []byte {
	return []byte(fmt.Sprintf(`[Unit]
Description=netOS: IKEv2 channel %s
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
Environment=STRONGSWAN_CONF=%s
ExecStart=/usr/sbin/charon-systemd
ExecStartPost=/usr/sbin/swanctl --load-all --uri %s --file %s --noprompt
ExecStartPost=/usr/sbin/swanctl --initiate --child netos-ch%d --uri %s --timeout 30
Restart=on-failure
RestartSec=5
RuntimeDirectory=%s
RuntimeDirectoryMode=0755
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW

[Install]
WantedBy=multi-user.target
`, ch.Name, p.daemon, ikev2ClientVICI(ch), p.conf, ch.Index, ikev2ClientVICI(ch), ikev2RuntimeName(ch)))
}

func (s *Subsystem) ensureIKEv2ClientInterface(ctx context.Context, ch config.Channel, wasOwned bool) (bool, error) {
	name := InterfaceName(ch)
	existed := s.linkExists(name)
	if existed && !wasOwned {
		return false, fmt.Errorf("интерфейс %s существует и не принадлежит netOS", name)
	}
	if !existed {
		if _, err := s.Runner.Run(ctx, "ip", "link", "add", name, "type", "xfrm", "if_id", fmt.Sprint(ikev2XFRMID(ch))); err != nil {
			return false, err
		}
	}
	ike, _ := ch.IKEv2Config()
	mtu := ike.MTU
	if mtu == 0 {
		mtu = 1200
	}
	if _, err := s.Runner.Run(ctx, "ip", "link", "set", "dev", name, "mtu", fmt.Sprint(mtu), "up"); err != nil {
		if !existed {
			_, _ = s.Runner.Run(ctx, "ip", "link", "delete", name)
		}
		return false, err
	}
	return !existed, nil
}

func (s *Subsystem) applyIKEv2(ctx context.Context, ch config.Channel, wasOwned, disableIPv6 bool) (created bool, retErr error) {
	ike, err := ch.IKEv2Config()
	if err != nil {
		return false, err
	}
	p := s.ikev2Paths(ch)
	snapshots, err := captureChannelFiles(p.conf, p.daemon, p.ca, p.unit)
	if err != nil {
		return false, err
	}
	created, err = s.ensureIKEv2ClientInterface(ctx, ch, wasOwned)
	if err != nil {
		return created, err
	}
	mutated := false
	defer func() {
		if retErr == nil {
			return
		}
		rollbackCtx := context.Background()
		if !wasOwned {
			s.cleanupIKEv2(rollbackCtx, ch)
			_, _ = s.Runner.Run(rollbackCtx, "ip", "-4", "rule", "del", "priority", fmt.Sprint(Priority(ch)))
			_, _ = s.Runner.Run(rollbackCtx, "ip", "-4", "route", "flush", "table", fmt.Sprint(TableNumber(ch)))
			return
		}
		if !mutated {
			return
		}
		if err := restoreChannelFiles(snapshots); err != nil {
			retErr = fmt.Errorf("%v; rollback IKEv2: %w", retErr, err)
			return
		}
		_, _ = s.Runner.Run(rollbackCtx, "systemctl", "daemon-reload")
		_, _ = s.Runner.Run(rollbackCtx, "systemctl", "restart", ikev2UnitName(ch))
	}()
	if err := os.MkdirAll(filepath.Dir(p.ca), 0o700); err != nil {
		return created, err
	}
	conf, daemon, ca, unit := renderIKEv2Client(ch, ike), renderIKEv2ClientDaemon(ch), []byte(ike.CACert), renderIKEv2ClientUnit(ch, p)
	changed := system.FileChanged(p.conf, conf) || system.FileChanged(p.daemon, daemon) || system.FileChanged(p.ca, ca) || system.FileChanged(p.unit, unit)
	for _, file := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{p.conf, conf, 0o600}, {p.daemon, daemon, 0o600}, {p.ca, ca, 0o644}, {p.unit, unit, 0o644},
	} {
		if err := writeFileIfChanged(file.path, file.data, file.mode); err != nil {
			return created, err
		}
		mutated = true
	}
	if changed {
		if _, err := s.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return created, err
		}
	}
	if err := s.ensureUnitEnabled(ctx, ikev2UnitName(ch)); err != nil {
		return created, err
	}
	active, _ := s.Runner.Run(ctx, "systemctl", "is-active", ikev2UnitName(ch))
	if changed || strings.TrimSpace(active) != "active" {
		if _, err := s.Runner.Run(ctx, "systemctl", "restart", ikev2UnitName(ch)); err != nil {
			return created, fmt.Errorf("запуск IKEv2: %w", err)
		}
	}
	deadline := time.Now().Add(35 * time.Second)
	for !s.openConnectReady(ctx, InterfaceName(ch)) {
		if !time.Now().Before(deadline) {
			return created, fmt.Errorf("IKEv2 не получил виртуальный IPv4-адрес на %s", InterfaceName(ch))
		}
		select {
		case <-ctx.Done():
			return created, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	if disableIPv6 {
		if err := s.suppressIPv6(InterfaceName(ch)); err != nil {
			return created, err
		}
	}
	if err := s.ensureRoutes(ctx, ch, InterfaceName(ch)); err != nil {
		return created, err
	}
	if err := s.ensureRule(ctx, ch); err != nil {
		return created, err
	}
	return created, nil
}

func (s *Subsystem) cleanupIKEv2(ctx context.Context, ch config.Channel) {
	unit := ikev2UnitName(ch)
	_, _ = s.Runner.Run(ctx, "systemctl", "disable", unit)
	_, _ = s.Runner.Run(ctx, "systemctl", "stop", unit)
	p := s.ikev2Paths(ch)
	_ = os.Remove(p.unit)
	_ = os.RemoveAll(p.root)
	if s.linkExists(InterfaceName(ch)) {
		_, _ = s.Runner.Run(ctx, "ip", "link", "delete", InterfaceName(ch))
	}
	_, _ = s.Runner.Run(ctx, "systemctl", "daemon-reload")
}
