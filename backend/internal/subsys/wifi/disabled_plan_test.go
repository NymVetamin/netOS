package wifi

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestDisabledSSIDChangesPreserveActiveRadio(t *testing.T) {
	runner := &fakeRunner{}
	s := testWiFiSubsystem(t, runner)
	old := wifiConfig()
	if err := s.Apply(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	next := wifiConfig()
	next.WiFi[0].SSIDs = append([]config.WiFiSSID{{ID: "disabled", SSID: "Stored only", Network: "home", Security: "open"}}, next.WiFi[0].SSIDs...)
	for _, operation := range []string{"add", "edit", "remove"} {
		t.Run(operation, func(t *testing.T) {
			if operation == "edit" {
				next.WiFi[0].SSIDs[0].SSID = "Changed stored name"
			}
			if operation == "remove" {
				next.WiFi[0].SSIDs = next.WiFi[0].SSIDs[1:]
			}
			before, _ := RenderRadio(old.WiFi[0], old)
			after, _ := RenderRadio(next.WiFi[0], next)
			if string(before) != string(after) {
				t.Fatal("disabled SSID changed active configuration")
			}
			if actions, err := s.Plan(old, next); err != nil || len(actions) != 0 {
				t.Fatalf("disabled edit planned restart: %v %v", actions, err)
			}
			runner.commands = nil
			if err := s.Apply(context.Background(), next); err != nil {
				t.Fatal(err)
			}
			for _, command := range runner.commands {
				if strings.Contains(command, " restart ") || strings.Contains(command, " stop ") || strings.Contains(command, " daemon-reload") {
					t.Fatalf("disabled edit mutated radio: %s", command)
				}
			}
		})
	}
	if !reflect.DeepEqual(old, wifiConfig()) {
		t.Fatal("planner modified source configuration")
	}
	next.WiFi[0].SSIDs = append(next.WiFi[0].SSIDs, config.WiFiSSID{ID: "new", SSID: "New active", Enabled: true, Network: "home", Security: "open"})
	if actions, err := s.Plan(old, next); err != nil || len(actions) != 1 || !actions[0].Disruptive {
		t.Fatalf("enable lost restart protection: %v %v", actions, err)
	}
	next = wifiConfig()
	next.WiFi[0].SSIDs = append(next.WiFi[0].SSIDs, config.WiFiSSID{ID: "off"})
	runner.active = false
	if actions, err := s.Plan(old, next); err != nil || len(actions) != 1 || !strings.Contains(actions[0].Detail, "расхождения") {
		t.Fatalf("live repair lost protection: %v %v", actions, err)
	}
}
