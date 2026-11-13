package api

import (
	"net/netip"
	"time"

	"github.com/netos-router/netos/internal/config"
)

const vpnHandshakeDetailLimit = 64

// Owned by the single monitor loop, not by browser reads or snapshot entries.
// Configuration renames can replace a snapshot without repeating a handshake.
type vpnHandshakeObserver struct {
	seen map[vpnHandshakeIdentity]int64
}

type vpnHandshakeIdentity struct {
	server, peer, publicKey, protocol string
	index                             int
}

type vpnHandshakeSample struct {
	server config.VPNServer
	rows   []vpnClientStatus
}

// Endpoint is current observation metadata, not the historical source address
// of the handshake. The kernel exposes only the latest successful handshake.
type vpnHandshakeRecord struct {
	Server     string `json:"server,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	Index      int    `json:"index,omitempty"`
	Peer       string `json:"peer,omitempty"`
	PeerName   string `json:"peer_name,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
	Handshake  int64  `json:"handshake,omitempty"`
	Observed   int64  `json:"observed"`
	Initial    bool   `json:"initial,omitempty"`
	Suppressed int    `json:"suppressed,omitempty"`
}

func (o *vpnHandshakeObserver) observe(samples []vpnHandshakeSample, now time.Time) []vpnHandshakeRecord {
	next := make(map[vpnHandshakeIdentity]int64)
	events := make([]vpnHandshakeRecord, 0)
	lost := 0
	for _, sample := range samples {
		server := sample.server
		if !server.Enabled || server.Type != "wireguard" {
			continue
		}
		protocol := "wireguard"
		if server.IsAmneziaWG() {
			protocol = "amneziawg"
		}
		rows := make(map[string]vpnClientStatus, len(sample.rows))
		for _, row := range sample.rows {
			rows[row.ID] = row
		}
		for _, peer := range server.Peers {
			if !peer.Enabled {
				continue
			}
			key := vpnHandshakeIdentity{server.ID, peer.ID, peer.Credentials["public_key"], protocol, server.Index}
			previous, known := o.seen[key]
			if !known {
				previous = -1 // no authoritative snapshot yet
			}
			next[key] = previous
			row, ok := rows[peer.ID]
			if !ok || row.PublicKey != key.publicKey || !row.TrafficKnown || (row.State != "recent" && row.State != "idle" && row.State != "never") {
				continue
			}
			if row.LastHandshake == 0 && previous < 0 {
				next[key] = 0
			}
			if row.LastHandshake <= 0 || row.LastHandshake > now.Unix() || row.LastHandshake == previous {
				continue
			}
			next[key] = row.LastHandshake
			if len(events) == vpnHandshakeDetailLimit {
				lost++
				continue
			}
			endpoint := ""
			if parsed, err := netip.ParseAddrPort(row.Endpoint); err == nil {
				endpoint = parsed.String()
			}
			serverName, peerName := server.Name, peer.Name
			if len(serverName) > 256 {
				serverName = ""
			}
			if len(peerName) > 256 {
				peerName = ""
			}
			if len(server.ID) > 128 || len(peer.ID) > 128 {
				lost++
				continue
			}
			events = append(events, vpnHandshakeRecord{Server: server.ID, ServerName: serverName, Index: server.Index, Peer: peer.ID, PeerName: peerName, Protocol: protocol, Endpoint: endpoint, Handshake: row.LastHandshake, Observed: now.Unix(), Initial: previous < 0})
		}
	}
	// Removed/disabled peers disappear here. Unknown telemetry retains its last
	// observation, so failure/retry cannot fabricate a repeated success event.
	o.seen = next
	if lost > 0 {
		events = append(events, vpnHandshakeRecord{Observed: now.Unix(), Suppressed: lost})
	}
	return events
}
