package qos

import (
	"context"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestDisabledQoSSettingsDoNotPlanOrApplyQueues(t *testing.T) {
	old := testConfig("static")
	old.QoS.Enabled = false
	next := *old
	next.QoS.WANs = []config.QoSWAN{{WAN: "wan1", UploadKbit: 12345, DownloadKbit: 54321, Diffserv: "besteffort"}}
	s := New(nil, t.TempDir())
	for _, pair := range [][2]*config.Config{{old, &next}, {&next, old}} {
		actions, err := s.Plan(pair[0], pair[1])
		if err != nil || len(actions) != 0 {
			t.Fatalf("disabled settings actions=%+v err=%v", actions, err)
		}
		// A nil runner also proves disabled edits execute no OS queue mutations.
		if err := s.Apply(context.Background(), pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	next.QoS.Enabled = true
	if actions, err := s.Plan(old, &next); err != nil || len(actions) != 1 || !actions[0].Disruptive {
		t.Fatalf("enable lost protection: %+v %v", actions, err)
	}
	next.QoS.Enabled = false
	next.Clients = []config.Client{{ID: "c", MAC: "02:00:00:00:00:01", Network: "lan", DownKbit: 1000}}
	if actions, err := s.Plan(old, &next); err != nil || len(actions) != 1 || !actions[0].Disruptive {
		t.Fatalf("client limit lost protection: %+v %v", actions, err)
	}
	next.Clients = nil
	if err := s.writeOwned([]ownedLink{{WAN: "wan1", Interface: "eth9", IFB: "ifb-netos-3"}}); err != nil {
		t.Fatal(err)
	}
	if actions, err := s.Plan(old, &next); err != nil || len(actions) != 1 || !actions[0].Disruptive {
		t.Fatalf("stale queues hidden: %+v %v", actions, err)
	}
}
