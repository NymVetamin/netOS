package config

// InterfaceEnabled includes administrative dependencies without changing the
// saved switch positions. A VLAN cannot operate over a disabled parent.
func (c *Config) InterfaceEnabled(id string) bool {
	seen := map[string]bool{}
	var enabled func(string) bool
	enabled = func(id string) bool {
		if seen[id] {
			return false
		}
		seen[id] = true
		for _, i := range c.Interfaces {
			if i.ID != id {
				continue
			}
			if !i.Enabled {
				return false
			}
			if i.Type == "vlan" && i.Parent != "" {
				return enabled(i.Parent)
			}
			return true
		}
		return false
	}
	return enabled(id)
}
func (c *Config) InterfaceNameEnabled(name string) bool {
	for _, i := range c.Interfaces {
		if i.Name == name {
			return c.InterfaceEnabled(i.ID)
		}
	}
	return false
}

// RuntimeNetworkConfig suspends uplinks whose interface was switched off.
// Desired WAN settings remain intact in the database, API and rollback snapshot.
func (c *Config) RuntimeNetworkConfig() *Config {
	if c == nil {
		return nil
	}
	out := *c
	out.Interfaces = append([]Interface(nil), c.Interfaces...)
	out.WANs = append([]WAN(nil), c.WANs...)
	enabled := c.InterfaceStates()
	for j := range out.Interfaces {
		out.Interfaces[j].Enabled = enabled[out.Interfaces[j].ID]
	}
	for j := range out.WANs {
		// Preserve handling of unknown interface references by validation/subsystems.
		if on, known := enabled[out.WANs[j].Interface]; known && !on {
			out.WANs[j].Enabled = false
		}
	}
	return &out
}

// InterfaceStates resolves administrative state for a single config snapshot.
// A missing parent or a VLAN cycle disables every link depending on it.
func (c *Config) InterfaceStates() map[string]bool {
	enabled := make(map[string]bool, len(c.Interfaces))
	parents := map[string]string{}
	for _, iface := range c.Interfaces {
		if _, known := enabled[iface.ID]; known {
			continue // InterfaceByID uses the first matching ID.
		}
		if iface.Enabled && iface.Type == "vlan" && iface.Parent != "" {
			parents[iface.ID] = iface.Parent
			enabled[iface.ID] = false
		} else {
			enabled[iface.ID] = iface.Enabled
		}
	}
	var resolve func(string) bool
	resolve = func(id string) bool {
		if parent, pending := parents[id]; pending {
			// Leave the default false visible to recursive visits of a cycle.
			delete(parents, id)
			enabled[id] = resolve(parent)
		}
		return enabled[id]
	}
	for id := range parents {
		resolve(id)
	}
	return enabled
}
