//go:build linux

package api

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/store"
	"github.com/netos-router/netos/internal/system"
)

type handshakeNativeLogger struct{ lifecycleLogger }

func (l *handshakeNativeLogger) Infof(format string, args ...any) {
	fmt.Printf("[инфо] "+format+"\n", args...)
	l.add(format, args...)
}

// Called only by the explicitly authorized isolated WG/AWG integration test,
// hosted in a transient netosd.service so journald supplies the real authority.
func checkNativeHandshakeJournal(t *testing.T, s *Server, server config.VPNServer, publicKey string, ping func()) {
	t.Helper()
	server.Name = "Native observed server"
	server.Peers = []config.VPNPeer{{ID: "observed-peer", Name: "Native peer", Enabled: true, Credentials: map[string]string{"public_key": publicKey}}}
	engine := apply.NewEngine(nil, true)
	if _, err := engine.Apply(context.Background(), config.Default(), 1, false); err != nil {
		t.Fatal(err)
	}
	engine.Current().VPNServers = []config.VPNServer{server}
	s.Engine = engine
	s.vpnStatus = map[string]*vpnStatusCache{"removed-baseline": {}}
	logger := &handshakeNativeLogger{}
	s.Logger = logger
	st, err := store.Open(filepath.Join(t.TempDir(), "logs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s.Store = st
	s.StorageRunner = &system.Exec{Timeout: 5 * time.Second, MaxOutputBytes: 4 << 20}
	from := time.Now().UTC()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.monitorVPNClients(ctx); close(done) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Error("monitor did not stop")
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		rows := s.vpnClients(context.Background(), server)
		s.vpnStatusMu.Lock()
		_, pendingBaseline := s.vpnStatus["removed-baseline"]
		s.vpnStatusMu.Unlock()
		if len(rows) == 1 && rows[0].State == "never" && !pendingBaseline {
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("missing native zero-handshake baseline")
	}
	if logger.String() != "" {
		t.Fatal("unconnected peer generated success")
	}
	ping()
	deadline = time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) && logger.String() == "" {
		time.Sleep(20 * time.Millisecond)
	}
	if strings.Count(logger.String(), vpnHandshakeMarker) != 1 {
		t.Fatal("missing or duplicated actual monitor event")
	}
	for i := 0; i < 32; i++ {
		s.vpnClients(context.Background(), server)
	}
	if strings.Count(logger.String(), vpnHandshakeMarker) != 1 {
		t.Fatal("browser reads repeated event")
	}
	cancel()
	<-done
	if _, err = s.StorageRunner.Run(context.Background(), "journalctl", "--sync"); err != nil {
		t.Fatal(err)
	}
	period := "from=" + url.QueryEscape(from.Format(time.RFC3339Nano)) + "&to=" + url.QueryEscape(time.Now().UTC().Format(time.RFC3339Nano)) + "&object=" + url.QueryEscape(server.ID)
	page := readAllJournalPages(t, s, "vpn", period)
	if len(page.Entries) != 1 {
		t.Fatal("native journal observation missing", len(page.Entries))
	}
	e := page.Entries[0]
	protocol := "wireguard"
	if server.IsAmneziaWG() {
		protocol = "amneziawg"
	}
	if e.Unit != "netosd.service" || e.Protocol != protocol || e.Result != "success" || !strings.Contains(e.Server, server.Name) || !strings.Contains(e.User, "Native peer") || strings.Contains(e.Event, "начале наблюдения") {
		t.Fatal(e)
	}
	all, code := allPageRequest(t, s, filepath.Join(t.TempDir(), "dns.log"), period)
	if code != 200 || len(all.Entries) != 1 || all.Entries[0].Source != "vpn" {
		t.Fatal("general canonical observation", code, all)
	}
	services := readAllJournalPages(t, s, "services", period)
	for _, e := range services.Entries {
		if strings.Contains(e.Message, vpnHandshakeMarker) {
			t.Fatal("observation duplicated in Services")
		}
	}
	t.Log("native WG/AWG existing monitor -> trusted journald -> VPN and General; baseline, successful handshake, repeat and browser reads PASS")
}
