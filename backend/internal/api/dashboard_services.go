package api

import (
	"context"
	"strings"
	"sync"
	"time"
)

type dashboardService struct {
	Unit     string `json:"unit"`
	Title    string `json:"title"`
	State    string `json:"state"`
	Substate string `json:"substate"`
}

type dashboardServiceCache struct {
	mu        sync.Mutex
	at        time.Time
	rows      []dashboardService
	available bool
}

func parseDashboardServices(raw string) []dashboardService {
	rows := []dashboardService{}
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !(strings.HasPrefix(f[0], "netos-") || f[0] == "netosd.service") || !strings.HasSuffix(f[0], ".service") {
			continue
		}
		title := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.Join(f[4:], " "), "netOS:"), "netOS"))
		rows = append(rows, dashboardService{Unit: f[0], Title: title, State: f[2], Substate: f[3]})
	}
	return rows
}

func (s *Server) dashboardServiceStatus(ctx context.Context) ([]dashboardService, bool) {
	c := &s.dashboardServices
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && time.Since(c.at) < 5*time.Second {
		return c.rows, c.available
	}
	c.rows, c.available = []dashboardService{}, false
	if s.Collector != nil && s.Collector.Runner != nil {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		// Listing loaded units never loads absent ones (unlike systemctl show).
		out, err := s.Collector.Runner.Run(ctx, "systemctl", "list-units", "--all", "--type=service", "--no-legend", "--no-pager", "--plain", "netos-*.service", "netosd.service")
		if err == nil {
			c.rows, c.available = parseDashboardServices(out), true
		}
	}
	c.at = time.Now()
	return c.rows, c.available
}
