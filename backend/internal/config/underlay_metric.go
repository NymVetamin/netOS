package config

// L2TPUnderlayMetric keeps provider access available for tunnel recovery while
// preferring every configured data-plane uplink over the L2TP underlay.
func (c *Config) L2TPUnderlayMetric(w WAN) int {
	metric := w.Metric + 10
	if c != nil && c.MultiWAN.Enabled {
		maximum := 0
		for _, candidate := range c.WANs {
			if candidate.Enabled && candidate.Metric > maximum {
				maximum = candidate.Metric
			}
		}
		metric += maximum
	}
	return metric
}
