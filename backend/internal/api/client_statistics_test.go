package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/netos-router/netos/internal/config"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStatisticsRangeBounds(t *testing.T) {
	for _, q := range []string{"minutes=0", "minutes=10081", "hours=-1", "from=1&to=2", "from=no&to=2"} {
		if _, _, err := statisticsRange(httptest.NewRequest("GET", "/api/statistics?"+q, nil)); err == nil {
			t.Errorf("accepted %s", q)
		}
	}
	a, b, err := statisticsRange(httptest.NewRequest("GET", "/api/statistics?minutes=5", nil))
	if err != nil || b.Sub(a) != 5*time.Minute {
		t.Fatalf("range %v %v %v", a, b, err)
	}
	now := time.Now().Unix()
	a, b, err = statisticsRange(httptest.NewRequest("GET", fmt.Sprintf("/api/statistics?from=%d&to=%d", now-600, now-300), nil))
	if err != nil || b.Sub(a) != 5*time.Minute {
		t.Fatal("custom range", err)
	}
}

func TestProxyClientCounterDirections(t *testing.T) {
	server := config.VPNServer{ID: "reality", Name: "Reality", Type: "xray", Enabled: true, Peers: []config.VPNPeer{{ID: "phone", Name: "Phone", Enabled: true}}}
	data, _ := json.Marshal(server)
	s := &Server{vpnStatus: map[string]*vpnStatusCache{"reality": {fingerprint: sha256.Sum256(data), at: time.Now(), rows: []vpnClientStatus{{ID: "phone", Received: 123, Sent: 456, TrafficKnown: true}}}}}
	out := s.ProxyClientCounters(context.Background(), &config.Config{VPNServers: []config.VPNServer{server}})
	if len(out) != 1 || out[0].RX != 456 || out[0].TX != 123 || out[0].ID != "vpn:reality:phone" {
		t.Fatalf("proxy attribution: %+v", out)
	}
}
