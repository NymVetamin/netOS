package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

type clientsRunner struct{ neighbors string }

func (r *clientsRunner) Run(context.Context, string, ...string) (string, error) {
	return r.neighbors, nil
}

func (r *clientsRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func TestClientsExcludeWANNeighbors(t *testing.T) {
	leases := filepath.Join(t.TempDir(), "dnsmasq.leases")
	if err := os.WriteFile(leases, []byte("1999999999 aa:bb:cc:dd:ee:01 192.168.10.20 phone *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &clientsRunner{neighbors: "" +
		"45.38.170.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE\n" +
		"192.168.10.20 dev br-lan lladdr aa:bb:cc:dd:ee:01 STALE\n" +
		"192.168.10.30 dev br-lan lladdr aa:bb:cc:dd:ee:02 REACHABLE\n"}
	c := NewCollector(runner, leases)
	got, err := c.Clients(context.Background(), map[string]bool{"br-lan": true})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("получено %d клиентов вместо 2: %+v", len(got), got)
	}
	for _, client := range got {
		if client.IP == "45.38.170.1" || client.Interface == "eth0" {
			t.Fatalf("WAN-шлюз попал в список клиентов: %+v", client)
		}
	}
	if got[0].IP != "192.168.10.20" || got[0].Source != "both" || !got[0].Online {
		t.Fatalf("аренда не объединена с локальным ARP: %+v", got[0])
	}
}
