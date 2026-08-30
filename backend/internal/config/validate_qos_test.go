package config

import "testing"

func TestValidateQoS(t *testing.T) {
	cfg := Default()
	cfg.Interfaces = []Interface{{ID: "wan-port", Name: "eth1", Type: "physical", Enabled: true}}
	cfg.WANs = []WAN{{ID: "wan1", Index: 1, Interface: "wan-port", Enabled: true, Proto: "dhcp"}}
	cfg.QoS = QoS{Enabled: true, WANs: []QoSWAN{
		{WAN: "wan1", UploadKbit: 10, DownloadKbit: 1000, Diffserv: "wrong"},
		{WAN: "wan1", UploadKbit: 1000, DownloadKbit: 20_000_000, Diffserv: "diffserv4"},
	}}
	result := cfg.Validate()
	for _, path := range []string{"qos.wans[0].upload_kbit", "qos.wans[0].diffserv", "qos.wans[1].wan", "qos.wans[1].download_kbit"} {
		found := false
		for _, problem := range result.Problems {
			if problem.Path == path {
				found = true
			}
		}
		if !found {
			t.Errorf("нет ошибки %s: %#v", path, result.Problems)
		}
	}
}
