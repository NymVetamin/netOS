package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestServicesRejectDNSRepliesAndPreserveLifecycle(t *testing.T) {
	raw := `{"_SYSTEMD_UNIT":"netos-unbound.service","PRIORITY":"6","MESSAGE":"info: 127.0.0.1 example.org. A IN NOERROR 0.1 0 74"}` + "\n" +
		`{"_PID":"1","_SYSTEMD_UNIT":"init.scope","UNIT":"netos-unbound.service","PRIORITY":"6","MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf","MESSAGE":"Started netos-unbound.service."}`
	rows, err := parseJournalEntries(raw, "services")
	if err != nil || len(rows) != 1 || rows[0].Unit != "netos-unbound.service" {
		t.Fatalf("DNS noise or missing target: %+v %v", rows, err)
	}
}

func TestServiceSeverityAndOriginalMessage(t *testing.T) {
	for _, tt := range []struct{ unit, priority, pid, id, message, event, severity string }{
		{"netos-test.service", "3", "", "", "failure detail", "Ошибка службы", "error"},
		{"netos-test.service", "4", "", "", "warning detail", "Предупреждение службы", "warning"},
		{"netosd.service", "6", "", "", "2026/11/13 [пред] TLS error", "Предупреждение службы", "warning"},
		{"netosd.service", "6", "", "", "2026/11/13 [ошиб] retry failed", "Ошибка службы", "error"},
		{"netos-xray-srv12.service", "6", "", "", "2026/11/13 17:00:00.123 [Warning] core: started", "Предупреждение службы", "warning"},
		{"netos-xray-ch12.service", "6", "", "", "[Error] bind failed", "Ошибка службы", "error"},
		{"netos-xray-ch12.service", "3", "", "", "[Warning] detail", "Ошибка службы", "error"},
		{"netos-xray-ch12.service", "6", "", "", "ordinary text [Error] detail", "", ""},
		{"netos-other.service", "6", "", "", "[Error] untrusted format", "", ""},
		{"netos-test.service", "6", "", "", "ordinary info", "", ""},
		{"netos-test.service", "6", "", "39f53479d3a045ac8e11786248231fbf", "untrusted manager id", "", ""},
		{"netos-test.service", "3", "1", "d9b373ed55a64feb8242e02dbe79a49c", "Failed with result exit-code", "Служба перешла в ошибку", "error"},
	} {
		raw, _ := json.Marshal(map[string]string{"_SYSTEMD_UNIT": tt.unit, "PRIORITY": tt.priority, "_PID": tt.pid, "MESSAGE_ID": tt.id, "MESSAGE": tt.message})
		rows, err := parseJournalEntries(string(raw), "services")
		if err != nil {
			t.Fatal(err)
		}
		if tt.event == "" {
			if len(rows) != 0 {
				t.Fatal("unexpected info", rows)
			}
			continue
		}
		if len(rows) != 1 || rows[0].Event != tt.event || rows[0].Severity != tt.severity || rows[0].Message != tt.message {
			t.Fatalf("%+v: %+v", tt, rows)
		}
	}
}

func TestXrayServiceDiagnosticsPrivacyAndClassification(t *testing.T) {
	for _, unit := range []string{"netos-xray-srv12.service", "netos-xray-ch12.service"} {
		for _, source := range []string{"services", "all"} {
			for _, priority := range []string{"3", "6"} {
				raw, _ := json.Marshal(map[string]string{
					"_SYSTEMD_UNIT": unit, "PRIORITY": priority,
					"MESSAGE": "2026/11/13 17:00:00.123 [Error] invalid uuid: sensitive-value",
				})
				rows, err := parseJournalEntries(string(raw), source)
				if err != nil || len(rows) != 1 || rows[0].Source != "services" || rows[0].Severity != "error" || strings.Contains(rows[0].Message, "sensitive-value") {
					t.Fatalf("%s/%s/%s: %+v %v", unit, source, priority, rows, err)
				}
				vpn, err := parseJournalEntries(string(raw), "vpn")
				if err != nil || len(vpn) != 0 {
					t.Fatalf("diagnostic duplicated into VPN: %+v %v", vpn, err)
				}
			}
		}
	}
}

func BenchmarkServiceLogParsing(b *testing.B) {
	for _, n := range []int{30, 600} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			raw := strings.Repeat(`{"__REALTIME_TIMESTAMP":"1794554000000000","_PID":"1","_SYSTEMD_UNIT":"init.scope","UNIT":"netos-test.service","PRIORITY":"6","MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf","MESSAGE":"Started netos-test.service."}`+"\n", n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rows, err := parseJournalEntries(raw, "services")
				if err != nil || len(rows) != n {
					b.Fatal(err, len(rows))
				}
				sortNewestFirst(rows)
			}
		})
	}
}
