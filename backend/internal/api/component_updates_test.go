package api

import (
	"context"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/netos-router/netos/internal/subsys/components"
)

func TestComponentScheduleRechecksConfigLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s := &Server{draftApplying: true}
		s.configOpMu.Lock()
		s.StartComponentUpdates(ctx, components.New(nil, nil), filepath.Join(t.TempDir(), "updates.json"))
		time.Sleep(time.Minute)
		synctest.Wait()
		first := s.ComponentUpdates.Snapshot()
		s.configOpMu.Unlock()
		time.Sleep(15 * time.Minute)
		synctest.Wait()
		second := s.ComponentUpdates.Snapshot()
		if first.Error != "идёт изменение конфигурации; повторите позже" ||
			second.Error != "идёт применение конфигурации" || !second.CheckedAt.IsZero() {
			t.Fatalf("first=%+v second=%+v", first, second)
		}
	})
}

func TestComponentUpdatePermissions(t *testing.T) {
	for _, section := range []string{"components", "system", "channels"} {
		for _, level := range []string{"view", "manage", "none"} {
			for _, method := range []string{"GET", "POST"} {
				r := limitedRequest(map[string]string{section: level})
				r.Method = method
				want := section == "components" && (level == "manage" || method == "GET" && level == "view")
				for _, path := range []string{"/api/components/updates", "/api/components/updates/install", "/api/components/xray/update"} {
					r.URL.Path = path
					if limitedEndpoint(r) != want {
						t.Fatalf("%s %s %s", section, level, method)
					}
				}
			}
		}
	}
}
