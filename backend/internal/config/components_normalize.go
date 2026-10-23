package config

import "sort"

// normalizeComponents gives the selection set one representation. Missing and
// installed:false both mean unselected; execution order comes from Catalog.
// Keep invalid entries intact so normalization cannot bypass validation.
func (c *Config) normalizeComponents() {
	seen := make(map[string]bool, len(c.Components))
	for _, component := range c.Components {
		if _, ok := ComponentByID(component.ID); !ok || seen[component.ID] {
			return
		}
		seen[component.ID] = true
	}
	selected := make([]Component, 0, len(c.Components))
	for _, component := range c.Components {
		if component.Installed {
			selected = append(selected, component)
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].ID < selected[j].ID })
	c.Components = selected
}
