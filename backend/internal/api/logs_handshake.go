package api

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const vpnHandshakeMarker = "netos-vpn-handshake-v1 "

func (s *Server) logVPNHandshakes(events []vpnHandshakeRecord) {
	if s.Logger == nil {
		return
	}
	for _, event := range events {
		raw, _ := json.Marshal(event)
		s.Logger.Infof("%s%s", vpnHandshakeMarker, raw)
	}
}

func vpnHandshakeLogFields(entry *logEntry, unit string) bool {
	if unit != "netosd.service" || len(entry.Message) > 8192 {
		return false
	}
	message := entry.Message
	if len(message) >= 20 && message[19] == ' ' {
		if _, err := time.Parse("2006/01/02 15:04:05", message[:19]); err == nil {
			message = message[20:]
		}
	}
	raw, ok := strings.CutPrefix(message, "[инфо] "+vpnHandshakeMarker)
	if !ok {
		return false
	}
	var record vpnHandshakeRecord
	if json.Unmarshal([]byte(raw), &record) != nil || record.Observed <= 0 {
		return false
	}
	if record.Suppressed > 0 {
		if record.Server != "" || record.Peer != "" || record.Handshake != 0 || record.Protocol != "" || record.Endpoint != "" || record.Initial || record.Index != 0 || record.ServerName != "" || record.PeerName != "" {
			return false
		}
		entry.Event = fmt.Sprintf("Не сохранены подробности наблюдений WG/AWG: %d", record.Suppressed)
		entry.Protocol, entry.Result, entry.Severity = "wireguard/amneziawg", "warning", "warning"
		return true
	}
	if record.Suppressed != 0 || (record.Protocol != "wireguard" && record.Protocol != "amneziawg") || record.Server == "" || record.Peer == "" || record.Index <= 0 || record.Handshake <= 0 || record.Handshake > record.Observed || len(record.Server) > 128 || len(record.Peer) > 128 || len(record.ServerName) > 256 || len(record.PeerName) > 256 {
		return false
	}
	if record.Endpoint != "" {
		if _, err := netip.ParseAddrPort(record.Endpoint); err != nil {
			return false
		}
	}
	entry.Protocol, entry.Result = record.Protocol, "success"
	entry.Server, entry.User = record.Server, record.Peer
	if record.ServerName != "" {
		entry.Server = record.ServerName + " (" + record.Server + ")"
	}
	if record.PeerName != "" {
		entry.User = record.PeerName + " (" + record.Peer + ")"
	}
	entry.Address = record.Endpoint
	entry.Event = "Обнаружено успешное рукопожатие"
	if record.Initial {
		entry.Event = "Последнее успешное рукопожатие при начале наблюдения"
	}
	entry.HandshakeTime = time.Unix(record.Handshake, 0).UTC().Format(time.RFC3339)
	return true
}
