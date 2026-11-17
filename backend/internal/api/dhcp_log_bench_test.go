package api

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/eventlog"
)

// Measures a renewal cycle through the real applied-configuration resolver.
// Configuration validation and initial lease population are setup, not renewals.
func BenchmarkDHCPLogRenewalBatch(b *testing.B) {
	for _, n := range []int{100, 1000, 4000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			cfg := config.Default()
			lines := make([]string, n)
			for i := 0; i < n; i++ {
				mac := fmt.Sprintf("02:00:00:00:%02x:%02x", i/256, i%256)
				cfg.Clients = append(cfg.Clients, config.Client{ID: fmt.Sprintf("c%d", i), MAC: mac, Name: "client"})
				lines[i] = fmt.Sprintf("DHCPACK(br0) 192.0.2.1 %s client", mac)
			}
			engine := apply.NewEngine(nil, true)
			if _, err := engine.Apply(context.Background(), cfg, 1, false); err != nil {
				b.Fatal(err)
			}
			s := &Server{Engine: engine, Events: eventlog.New()}
			lan := &eventlog.LAN{Log: s.Events, Names: s.lanNames()}
			for _, line := range lines {
				lan.DHCP(time.Time{}, line)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, line := range lines {
					lan.DHCP(time.Time{}, line)
				}
			}
		})
	}
}
