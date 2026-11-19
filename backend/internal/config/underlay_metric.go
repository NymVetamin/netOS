package config

import (
	"fmt"
	"math"
)

// L2TPMetricBase places provider routes behind every active Multi-WAN uplink.
func (c *Config) L2TPMetricBase() int {
	maximum := 0
	if c.MultiWAN.Enabled {
		for _, wan := range c.WANs {
			if wan.Enabled && wan.Metric > maximum {
				maximum = wan.Metric
			}
		}
	}
	return maximum
}

func (w WAN) L2TPUnderlayMetric(base int) (int, error) {
	// pppd reads the tunnel priority as a signed int; ip route reads the
	// provider priority as uint32. Check before adding user-supplied ints.
	if w.Metric <= 0 || w.Metric > math.MaxInt32 {
		return 0, fmt.Errorf("приоритет L2TP должен быть в диапазоне 1–%d", math.MaxInt32)
	}
	if base > math.MaxUint32-10-w.Metric {
		return 0, fmt.Errorf("приоритет сети провайдера с учётом аплинков превышает %d", int64(math.MaxUint32))
	}
	return base + w.Metric + 10, nil
}
