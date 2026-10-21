package api

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type dashboardResources struct {
	CPU         *float64 `json:"cpu_percent"`
	MemoryTotal *uint64  `json:"memory_total"`
	MemoryUsed  *uint64  `json:"memory_used"`
	Temperature *float64 `json:"cpu_temperature"`
}

type dashboardMetrics struct {
	mu          sync.Mutex
	at          time.Time
	total, idle uint64
	cpu         *float64
}

func cpuCounters(raw string) (total, idle uint64, ok bool) {
	fields := strings.Fields(strings.SplitN(raw, "\n", 2)[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return
	}
	// guest/guest_nice are already included in user/nice.
	for i := 1; i < len(fields) && i <= 8; i++ {
		n, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			return 0, 0, false
		}
		total += n
		if i == 4 || i == 5 {
			idle += n
		}
	}
	return total, idle, true
}

func memoryUsage(raw string) (total, used *uint64) {
	values := map[string]uint64{}
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[2] != "kB" {
			continue
		}
		n, err := strconv.ParseUint(f[1], 10, 64)
		if err == nil {
			values[strings.TrimSuffix(f[0], ":")] = n * 1024
		}
	}
	t, tok := values["MemTotal"]
	a, aok := values["MemAvailable"]
	if !tok || !aok || t == 0 || a > t {
		return nil, nil
	}
	u := t - a
	return &t, &u
}

func cpuTemperature(sys string) *float64 {
	var hottest *float64
	add := func(path string) {
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
		v /= 1000
		if err == nil && v > 0 && v < 150 && (hottest == nil || v > *hottest) {
			hottest = &v
		}
	}
	monitors, _ := filepath.Glob(filepath.Join(sys, "class/hwmon/hwmon*"))
	for _, monitor := range monitors {
		name, _ := os.ReadFile(filepath.Join(monitor, "name"))
		switch strings.TrimSpace(string(name)) {
		case "coretemp", "k10temp", "zenpower", "cpu_thermal":
			inputs, _ := filepath.Glob(filepath.Join(monitor, "temp*_input"))
			for _, path := range inputs {
				add(path)
			}
		}
	}
	if hottest != nil {
		return hottest
	}
	zones, _ := filepath.Glob(filepath.Join(sys, "class/thermal/thermal_zone*"))
	for _, zone := range zones {
		name, _ := os.ReadFile(filepath.Join(zone, "type"))
		n := strings.ToLower(strings.TrimSpace(string(name)))
		if strings.Contains(n, "cpu") || strings.Contains(n, "x86_pkg") {
			add(filepath.Join(zone, "temp"))
		}
	}
	return hottest
}

func (m *dashboardMetrics) read(proc, sys string) dashboardResources {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := dashboardResources{Temperature: cpuTemperature(sys)}
	mem, _ := os.ReadFile(filepath.Join(proc, "meminfo"))
	result.MemoryTotal, result.MemoryUsed = memoryUsage(string(mem))
	stat, err := os.ReadFile(filepath.Join(proc, "stat"))
	total, idle, ok := cpuCounters(string(stat))
	if err != nil || !ok {
		m.at = time.Time{}
		m.cpu = nil
		return result
	}
	now := time.Now()
	if m.at.IsZero() || now.Sub(m.at) >= time.Second {
		m.cpu = nil
		if !m.at.IsZero() && now.Sub(m.at) < 30*time.Second && total > m.total && idle >= m.idle && idle-m.idle <= total-m.total {
			v := 100 * float64((total-m.total)-(idle-m.idle)) / float64(total-m.total)
			m.cpu = &v
		}
		m.total, m.idle, m.at = total, idle, now
	}
	result.CPU = m.cpu
	return result
}
