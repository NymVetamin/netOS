package config

import "fmt"

// A server has one cryptokey default route. Keep its channel identity stable
// while allowing the operator to rename it and adjust probes/failure handling.
func WireGuardPeerChannelID(serverID string) string { return "wg-exit-" + serverID }

func (c *Config) normalizeWireGuardPeerChannels() {
	sources := map[string]WireGuardPeerChannel{}
	names := map[string]string{}
	protocols := map[string]string{}
	var order []string
	for _, s := range c.VPNServers {
		if !IsWireGuardType(s.Type) {
			continue
		}
		for _, p := range s.Peers {
			if !p.UseAsChannel {
				continue
			}
			id := WireGuardPeerChannelID(s.ID)
			if _, exists := sources[id]; exists {
				continue
			} // validation reports multiple exits
			sources[id] = WireGuardPeerChannel{s.ID, p.ID, s.Index}
			names[id] = p.Name
			protocols[id] = s.Type
			order = append(order, id)
		}
	}
	used := map[int]bool{}
	present := map[string]bool{}
	managedNAT := map[string]string{}
	out := make([]Channel, 0, len(c.Channels)+len(order))
	for _, ch := range c.Channels {
		used[ch.Index] = true
		if ch.WireGuardPeer != nil {
			ref, exists := sources[ch.ID]
			if !exists {
				managedNAT["channel-nat-"+ch.ID] = ""
				continue
			}
			ch.WireGuardPeer = &ref
			ch.Type = protocols[ch.ID]
			managedNAT["channel-nat-"+ch.ID] = fmt.Sprintf("%s-srv%d", WireGuardPrefix(ch.Type), ref.ServerIndex)
		}
		present[ch.ID] = true
		out = append(out, ch)
	}
	candidate := 1
	for _, id := range order {
		if present[id] {
			continue
		}
		for used[candidate] {
			candidate++
		}
		ref := sources[id]
		out = append(out, Channel{ID: id, Index: candidate, Name: names[id], Enabled: true, Type: protocols[id], Mode: "tun", FailMode: "block", Probe: DefaultProbe(), Config: map[string]any{}, WireGuardPeer: &ref})
		used[candidate] = true
	}
	c.Channels = out
	nat := c.Firewall.NAT[:0]
	for _, rule := range c.Firewall.NAT {
		if iface, known := managedNAT[rule.ID]; known && rule.System {
			if iface == "" {
				continue
			}
			rule.Interface = iface
		}
		nat = append(nat, rule)
	}
	c.Firewall.NAT = nat
}

func (c *Config) validateWireGuardPeerChannels(r *ValidationResult) {
	sources := map[string]WireGuardPeerChannel{}
	active := map[string]bool{}
	protocols := map[string]string{}
	for si, s := range c.VPNServers {
		count := 0
		for pi, p := range s.Peers {
			if !p.UseAsChannel {
				continue
			}
			count++
			path := fmt.Sprintf("vpn_servers[%d].peers[%d].use_as_channel", si, pi)
			if !IsWireGuardType(s.Type) {
				r.errf(path, "выход через клиента поддерживают WireGuard и AmneziaWG")
			}
			id := WireGuardPeerChannelID(s.ID)
			sources[id] = WireGuardPeerChannel{s.ID, p.ID, s.Index}
			active[id] = s.Enabled && p.Enabled
			protocols[id] = s.Type
			if p.Channel == id || (p.Channel == "" && s.DefaultChannel == id) {
				r.errf(path, "клиент выхода не может направлять собственный трафик в себя")
			}
		}
		if count > 1 {
			r.errf(fmt.Sprintf("vpn_servers[%d].peers", si), "на одном WG-сервере допускается один клиент выхода")
		}
	}
	found := map[string]bool{}
	for i, ch := range c.Channels {
		expected, exists := sources[ch.ID]
		if ch.WireGuardPeer == nil && !exists {
			continue
		}
		path := fmt.Sprintf("channels[%d].wireguard_peer", i)
		if ch.WireGuardPeer == nil || !exists || *ch.WireGuardPeer != expected || !IsWireGuardType(ch.Type) || ch.Type != protocols[ch.ID] || ch.Mode != "tun" || len(ch.Config) != 0 {
			r.errf(path, "канал должен ссылаться на выбранного клиента WG-сервера без отдельной конфигурации туннеля")
			continue
		}
		found[ch.ID] = true
		if ch.Enabled && !active[ch.ID] {
			r.errf(path, "для включённого канала включите WG-сервер и клиента выхода")
		}
	}
	for id := range sources {
		if !found[id] {
			r.errf("channels", "отсутствует связанный WG-канал %s", id)
		}
	}
}
