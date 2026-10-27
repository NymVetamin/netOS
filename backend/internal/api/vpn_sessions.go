package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/subsys/vpnservers"
	"github.com/netos-router/netos/internal/system"
)

type vpnStatusCache struct {
	mu          sync.Mutex
	fingerprint [32]byte
	at          time.Time
	rows        []vpnClientStatus
	refreshing  chan struct{}
}

// Keep the last observed connection while the daemon runs, including when no
// browser is open. This is observation time, not a fabricated disconnect time.
func (s *Server) monitorVPNClients(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		cycleStarted := time.Now()
		if s.Engine != nil {
			servers := s.Engine.Current().VPNServers
			keep := map[string]bool{}
			var wg sync.WaitGroup
			slots := make(chan struct{}, 4)
			for _, server := range servers {
				keep[server.ID] = true
				select {
				case slots <- struct{}{}:
				case <-ctx.Done():
					return
				}
				wg.Add(1)
				go func(server config.VPNServer) {
					defer wg.Done()
					defer func() { <-slots }()
					s.vpnClientSnapshot(ctx, server, cycleStarted)
				}(server)
			}
			wg.Wait()
			s.vpnStatusMu.Lock()
			for id := range s.vpnStatus {
				if !keep[id] {
					delete(s.vpnStatus, id)
				}
			}
			s.vpnStatusMu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) vpnClients(ctx context.Context, server config.VPNServer) []vpnClientStatus {
	rows, _ := s.vpnClientSnapshot(ctx, server, time.Time{})
	return rows
}

// Only the monitor refreshes a warm snapshot. Cold/configuration-changed reads
// are coalesced without holding the snapshot lock across external commands.
// A concurrent cold read can satisfy a cycle.
func (s *Server) vpnClientSnapshot(ctx context.Context, server config.VPNServer, refreshAfter time.Time) ([]vpnClientStatus, time.Time) {
	data, _ := json.Marshal(server)
	fingerprint := sha256.Sum256(data)
	s.vpnStatusMu.Lock()
	if s.vpnStatus == nil {
		s.vpnStatus = map[string]*vpnStatusCache{}
	}
	cache := s.vpnStatus[server.ID]
	if cache == nil || cache.fingerprint != fingerprint {
		// An old configuration's in-flight result belongs only to its old entry.
		cache = &vpnStatusCache{fingerprint: fingerprint}
		s.vpnStatus[server.ID] = cache
	}
	s.vpnStatusMu.Unlock()
	for {
		cache.mu.Lock()
		if !cache.at.IsZero() && (refreshAfter.IsZero() || !cache.at.Before(refreshAfter)) {
			rows, at := append([]vpnClientStatus{}, cache.rows...), cache.at
			cache.mu.Unlock()
			return rows, at
		}
		if ctx.Err() != nil {
			cache.mu.Unlock()
			return nil, time.Time{}
		}
		if done := cache.refreshing; done != nil {
			cache.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, time.Time{}
			}
		}
		cache.refreshing = make(chan struct{})
		cache.mu.Unlock()
		break
	}
	defer func() {
		cache.mu.Lock()
		close(cache.refreshing)
		cache.refreshing = nil
		cache.mu.Unlock()
	}()
	caller := ctx
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	now := time.Now()
	var rows []vpnClientStatus
	if server.Type == "wireguard" {
		rows = s.wireGuardClients(ctx, server, now)
	} else {
		rows = s.sessionClients(ctx, server)
	}
	previous := map[string]vpnClientStatus{}
	cache.mu.Lock()
	for _, row := range cache.rows {
		previous[row.ID] = row
	}
	cache.mu.Unlock()
	for i := range rows {
		row := &rows[i]
		row.LastSeen = previous[row.ID].LastSeen
		if row.LastHandshake > 0 {
			row.LastSeen = row.LastHandshake
		}
		if row.State == "online" {
			row.LastSeen = now.Unix()
		}
	}
	if caller.Err() != nil {
		return rows, time.Time{}
	}
	cache.mu.Lock()
	cache.rows, cache.at = rows, time.Now()
	at := cache.at
	cache.mu.Unlock()
	return append([]vpnClientStatus{}, rows...), at
}

func (s *Server) sessionClients(ctx context.Context, server config.VPNServer) []vpnClientStatus {
	rows := make([]vpnClientStatus, 0, len(server.Peers))
	live := map[string]vpnClientStatus{}
	available := false
	if server.Enabled && s.Collector != nil && s.Collector.Runner != nil {
		run := s.Collector.Runner.Run
		var out string
		var err error
		switch server.Type {
		case "ocserv":
			out, err = run(ctx, "occtl", "--socket-file", fmt.Sprintf("/run/netos-ocserv-srv%d/occtl.socket", server.Index), "--json", "show", "users")
			if err == nil {
				live, available = ocservSessions(out)
			}
		case "ikev2":
			out, err = run(ctx, "/usr/sbin/swanctl", "--list-sas", "--raw", "--ike", fmt.Sprintf("netos-srv%d", server.Index), "--uri", "unix:///run/netos-strongswan/charon.vici")
			if err == nil {
				live, available = ikev2Sessions(out, fmt.Sprintf("netos-srv%d", server.Index))
			}
		case "l2tp":
			out, err = run(ctx, "ip", "-j", "-s", "address", "show")
			if err == nil {
				live, available = pppSessions(out, config.L2TPInterfacePrefix(server.Index)+"+")
			}
		case "xray":
			out, err = system.XrayUserStats(ctx, s.Collector.Runner, vpnservers.XrayStatsSocket(server))
			if err == nil {
				live, available = xraySessions(out)
			}
		}
	}
	for _, peer := range server.Peers {
		row := vpnClientStatus{ID: peer.ID, PublicKey: peer.Credentials["public_key"], State: "unknown"}
		switch {
		case !server.Enabled:
			row.State = "server_disabled"
		case !peer.Enabled:
			row.State = "disabled"
		case available:
			identity := peer.Credentials["username"]
			switch server.Type {
			case "ocserv":
				identity = server.OcservUsername(peer)
			case "l2tp":
				identity = peer.Address
			case "xray":
				xr, err := server.XrayConfig()
				if err != nil {
					rows = append(rows, row)
					continue
				}
				if xr.Protocol != "socks" && xr.Protocol != "http" {
					identity = server.ID + "/" + peer.ID
				}
			}
			row.State = "offline"
			if session, ok := live[identity]; ok && identity != "" {
				row.State, row.Endpoint, row.Received, row.Sent, row.TrafficKnown = session.State, session.Endpoint, session.Received, session.Sent, session.TrafficKnown
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func mergeSession(rows map[string]vpnClientStatus, identity string, row vpnClientStatus) {
	if identity == "" {
		return
	}
	old := rows[identity]
	if old.State == "online" {
		row.State = "online"
	}
	if old.Endpoint != "" && old.Endpoint != row.Endpoint {
		if row.Endpoint == "" {
			row.Endpoint = old.Endpoint
		} else {
			row.Endpoint = old.Endpoint + ", " + row.Endpoint
		}
	}
	row.Received += old.Received
	row.Sent += old.Sent
	rows[identity] = row
}

func ocservSessions(raw string) (map[string]vpnClientStatus, bool) {
	var sessions []struct {
		Username string      `json:"Username"`
		State    string      `json:"State"`
		Endpoint string      `json:"Remote IP"`
		RX       json.Number `json:"RX"`
		TX       json.Number `json:"TX"`
	}
	if !strings.HasPrefix(strings.TrimSpace(raw), "[") || json.Unmarshal([]byte(raw), &sessions) != nil {
		return nil, false
	}
	rows := map[string]vpnClientStatus{}
	for _, session := range sessions {
		if session.State == "" || session.Username == "" {
			return nil, false
		}
		if session.State != "connected" {
			continue
		}
		row := vpnClientStatus{State: "online", Endpoint: session.Endpoint}
		if session.RX != "" && session.TX != "" {
			rx, errRX := strconv.ParseUint(string(session.RX), 10, 64)
			tx, errTX := strconv.ParseUint(string(session.TX), 10, 64)
			if errRX == nil && errTX == nil {
				row.Received, row.Sent, row.TrafficKnown = rx, tx, true
			}
		}
		mergeSession(rows, session.Username, row)
	}
	return rows, true
}

// VICI raw output has nested IKE/CHILD sections. Only authenticated IKE SAs
// with an installed child count as online; never match an unauthenticated ID.
func ikev2Sessions(raw, connection string) (map[string]vpnClientStatus, bool) {
	rows := map[string]vpnClientStatus{}
	depth := 0
	name, previous, identity, remoteID, endpoint, port, state := "", "", "", "", "", "", ""
	childInstalled, installed := false, false
	var received, sent, childRX, childTX uint64
	for _, token := range strings.Fields(strings.NewReplacer("{", " { ", "}", " } ").Replace(raw)) {
		switch token {
		case "{":
			depth++
			if depth == 2 {
				name = previous
				identity, remoteID, endpoint, port, state = "", "", "", "", ""
				installed = false
				received, sent = 0, 0
			}
			if depth == 4 {
				childInstalled = false
				childRX, childTX = 0, 0
			}
		case "}":
			if depth == 4 && childInstalled {
				installed = true
				received += childRX
				sent += childTX
			}
			if depth == 2 && name == connection && state == "ESTABLISHED" && installed {
				// strongSwan omits remote-eap-id when it equals remote-id.
				if identity == "" {
					identity = remoteID
				}
				if port != "" && net.ParseIP(endpoint) != nil {
					endpoint = net.JoinHostPort(endpoint, port)
				}
				mergeSession(rows, identity, vpnClientStatus{State: "online", Endpoint: endpoint, Received: received, Sent: sent, TrafficKnown: true})
			}
			depth--
			if depth < 0 {
				return nil, false
			}
		default:
			key, value, ok := strings.Cut(token, "=")
			if ok {
				if depth == 2 {
					switch key {
					case "remote-eap-id":
						identity = value
					case "remote-id":
						remoteID = value
					case "remote-host":
						endpoint = value
					case "remote-port":
						port = value
					case "state":
						state = value
					}
				}
				if depth == 4 {
					switch key {
					case "state":
						childInstalled = value == "INSTALLED"
					case "bytes-in":
						childRX, _ = strconv.ParseUint(value, 10, 64)
					case "bytes-out":
						childTX, _ = strconv.ParseUint(value, 10, 64)
					}
				}
			}
		}
		previous = token
	}
	// swanctl emits a final reply even for zero SAs. Arbitrary output must not
	// become an authoritative empty session list (plugin warnings may precede it).
	return rows, depth == 0 && strings.Contains(raw, "list-sas reply {")
}

func pppSessions(raw, name string) (map[string]vpnClientStatus, bool) {
	var interfaces []struct {
		Name      string   `json:"ifname"`
		Flags     []string `json:"flags"`
		Addresses []struct {
			Peer    string `json:"peer"`
			Address string `json:"address"`
		} `json:"addr_info"`
		Stats *struct {
			RX struct {
				Bytes uint64 `json:"bytes"`
			} `json:"rx"`
			TX struct {
				Bytes uint64 `json:"bytes"`
			} `json:"tx"`
		} `json:"stats64"`
	}
	if !strings.HasPrefix(strings.TrimSpace(raw), "[") || json.Unmarshal([]byte(raw), &interfaces) != nil {
		return nil, false
	}
	rows := map[string]vpnClientStatus{}
	for _, iface := range interfaces {
		if iface.Name != name && !(strings.HasSuffix(name, "+") && strings.HasPrefix(iface.Name, strings.TrimSuffix(name, "+"))) {
			continue
		}
		up, pointToPoint := false, false
		for _, flag := range iface.Flags {
			if flag == "UP" {
				up = true
			}
			if flag == "POINTOPOINT" {
				pointToPoint = true
			}
		}
		if !up || !pointToPoint {
			continue
		}
		for _, addr := range iface.Addresses {
			address := addr.Peer
			if address == "" {
				address = addr.Address
			}
			peer := strings.Split(address, "/")[0]
			if net.ParseIP(peer) == nil {
				continue
			}
			row := vpnClientStatus{State: "online"}
			if iface.Stats != nil {
				row.Received, row.Sent, row.TrafficKnown = iface.Stats.RX.Bytes, iface.Stats.TX.Bytes, true
			}
			rows[peer] = row
		}
	}
	return rows, true
}

func xraySessions(raw string) (map[string]vpnClientStatus, bool) {
	var response struct {
		Users []struct {
			Email string `json:"email"`
			IPs   []struct {
				IP string `json:"ip"`
			} `json:"ips"`
			Traffic *struct {
				Up   json.Number `json:"uplink"`
				Down json.Number `json:"downlink"`
			} `json:"traffic"`
		} `json:"users"`
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &fields) != nil || fields == nil || json.Unmarshal([]byte(raw), &response) != nil {
		return nil, false
	}
	for key := range fields {
		if key != "users" {
			return nil, false
		}
	}
	rows := map[string]vpnClientStatus{}
	for _, user := range response.Users {
		if user.Email == "" {
			return nil, false
		}
		row := vpnClientStatus{State: "offline"}
		ips := []string{}
		for _, entry := range user.IPs {
			if net.ParseIP(strings.Trim(entry.IP, "[]")) == nil {
				return nil, false
			}
			ips = append(ips, entry.IP)
		}
		if len(ips) > 0 {
			row.State = "online"
			sort.Strings(ips)
			row.Endpoint = strings.Join(ips, ", ")
		}
		if user.Traffic != nil {
			var err error
			up, down := string(user.Traffic.Up), string(user.Traffic.Down)
			// Xray omits zero protobuf fields, including the entire users array
			// when no one is connected.
			if up == "" {
				up = "0"
			}
			if down == "" {
				down = "0"
			}
			row.Received, err = strconv.ParseUint(up, 10, 64)
			if err != nil {
				return nil, false
			}
			row.Sent, err = strconv.ParseUint(down, 10, 64)
			if err != nil {
				return nil, false
			}
			row.TrafficKnown = true
		}
		rows[user.Email] = row
	}
	return rows, true
}
