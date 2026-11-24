package qos

import (
	"context"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestUploadOnlyRateUpdatePreservesQueues(t *testing.T) {
	for _, mode := range []string{"rate", "unchanged", "unknown root", "extra class", "wrong MAC", "missing ingress"} {
		t.Run(mode, func(t *testing.T) {
			outputs := map[string]string{
				"tc -j qdisc show dev lan0":               `[{"kind":"noqueue","handle":"0:","root":true,"refcnt":2,"options":{}},{"kind":"ingress","handle":"ffff:","parent":"ffff:fff1","options":{}}]`,
				"tc -j class show dev lan0":               `[]`,
				"tc -j filter show dev lan0 parent ffff:": `[{"protocol":"all","pref":100,"kind":"flower","chain":0,"options":{"handle":1,"keys":{"src_mac":"02:00:00:00:00:02"},"not_in_hw":true,"actions":[{"order":1,"kind":"police","index":1,"control_action":{"type":"drop"},"overhead":0,"ref":1,"bind":1}]}}]`,
				"tc filter show dev lan0 parent ffff:":    "filter protocol all pref 100 flower src_mac 02:00:00:00:00:02 action police rate 1000kbit burst 64Kb mtu 64Kb",
			}
			client := config.Client{MAC: "02:00:00:00:00:02", UpKbit: 500}
			switch mode {
			case "unchanged":
				client.UpKbit = 1000
			case "unknown root":
				outputs["tc -j qdisc show dev lan0"] = strings.ReplaceAll(outputs["tc -j qdisc show dev lan0"], "noqueue", "fq_codel")
			case "extra class":
				outputs["tc -j class show dev lan0"] = `[{"class":"htb","handle":"1:1"}]`
			case "wrong MAC":
				client.MAC = "02:00:00:00:00:03"
			case "missing ingress":
				outputs["tc -j qdisc show dev lan0"] = `[{"kind":"noqueue","handle":"0:","root":true,"options":{}}]`
			}
			runner := &fakeRunner{outputs: outputs}
			ok, err := New(runner, t.TempDir()).updateClientRates(context.Background(), clientInterface{Name: "lan0", Upload: []config.Client{client}})
			if err != nil || ok != (mode == "rate" || mode == "unchanged") {
				t.Fatalf("handled=%v err=%v", ok, err)
			}
			mutations := 0
			for _, command := range runner.commands {
				if strings.Contains(command, " replace ") {
					mutations++
					if !strings.HasPrefix(command, "tc filter replace ") {
						t.Fatal(command)
					}
				}
				if strings.Contains(command, " del ") {
					t.Fatal(command)
				}
			}
			want := 0
			if mode == "rate" {
				want = 1
			}
			if mutations != want {
				t.Fatalf("mutations=%d want=%d", mutations, want)
			}
		})
	}
}
