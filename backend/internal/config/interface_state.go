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
	for j := range out.Interfaces {
		out.Interfaces[j].Enabled = c.InterfaceEnabled(out.Interfaces[j].ID)
	}
	for j := range out.WANs {
		// Preserve handling of unknown interface references by validation/subsystems.
		for _, i := range c.Interfaces {
			if i.ID == out.WANs[j].Interface && !c.InterfaceEnabled(i.ID) {
				out.WANs[j].Enabled = false
			}
		}
	}
	return &out
}
