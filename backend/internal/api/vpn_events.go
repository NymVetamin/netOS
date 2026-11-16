package api

import (
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/eventlog"
)

// vpnPresence remembers, per server and peer, whether the last authoritative
// observation was "connected". It turns the existing 5-second monitor
// snapshots into connect/disconnect events without any extra command.
// Owned by monitorVPNClients only. Size: one entry per configured peer.
type vpnPresence struct {
	seen    map[string]bool
	started bool
}

// vpnOnline reads the monitor's state. Unknown telemetry (a failed command,
// an unavailable daemon) is not evidence of a disconnect and changes nothing.
func vpnOnline(state string) (online, known bool) {
	switch state {
	case "online", "recent": // session listed; WireGuard handshake younger than 180 s
		return true, true
	case "offline", "idle", "never", "disabled", "server_disabled":
		return false, true
	}
	return false, false
}

// observe compares one monitor cycle with the previous one. rows[i] is nil
// when the snapshot of servers[i] was not taken.
func (p *vpnPresence) observe(log *eventlog.Log, servers []config.VPNServer, rows [][]vpnClientStatus, now time.Time) {
	next := make(map[string]bool, len(p.seen))
	for i, server := range servers {
		names := make(map[string]string, len(server.Peers))
		for _, peer := range server.Peers {
			names[peer.ID] = peer.Name
		}
		if rows[i] == nil {
			for id := range names {
				if was, ok := p.seen[server.ID+"\x00"+id]; ok {
					next[server.ID+"\x00"+id] = was
				}
			}
			continue
		}
		for _, row := range rows[i] {
			key := server.ID + "\x00" + row.ID
			online, known := vpnOnline(row.State)
			was, had := p.seen[key]
			if !known {
				if had {
					next[key] = was
				}
				continue
			}
			next[key] = online
			// Disabling a peer or server is the administrator's action, not a
			// client's disconnect; it is not reported here.
			if (had && was == online) || (!had && !online) || row.State == "disabled" || row.State == "server_disabled" {
				continue
			}
			name := names[row.ID]
			if name == "" {
				name = row.ID
			}
			from := ""
			if row.Endpoint != "" {
				from = " с " + row.Endpoint
			}
			msg := name + " подключился" + from
			switch {
			case !online && server.Type == "wireguard":
				msg = name + " отключился: нет рукопожатий 3 мин (примерно)"
			case !online:
				msg = name + " отключился"
			case !had && !p.started:
				msg = name + " подключён" + from + " (на момент запуска netOS)"
			}
			log.Add(now, eventlog.VPN, eventlog.Info, server.Name, msg)
		}
	}
	p.seen, p.started = next, true
}

// vpnServerName names a VPN server for daemon messages, which know only the
// type and index from unit or connection names.
func (s *Server) vpnServerName(typ string, index int) string {
	if s.Engine == nil || s.Engine.Current() == nil {
		return ""
	}
	for _, server := range s.Engine.Current().VPNServers {
		if server.Index == index && server.Type == typ {
			return server.Name
		}
	}
	return ""
}
