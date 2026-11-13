package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/xraylog"
)

func TestXrayDiagnosticOutputChild(t *testing.T) {
	if os.Getenv("NETOS_DIAGNOSTIC_OUTPUT_CHILD") != "1" {
		return
	}
	for i := 0; i < 20; i++ {
		fmt.Println("[Warning] diagnostic message")
	}
	os.Exit(0)
}

func TestXrayDiagnosticLossDoesNotMarkResourceHistory(t *testing.T) {
	t.Setenv("NETOS_DIAGNOSTIC_OUTPUT_CHILD", "1")
	var output bytes.Buffer
	if err := xraylog.Run(context.Background(), os.Args[0], []string{"-test.run=^TestXrayDiagnosticOutputChild$"}, &output); err != nil {
		t.Fatal(err)
	}
	x, _ := resourceFixture()
	h, err := NewClientHistory(filepath.Join(t.TempDir(), "history.db"), nil, nil, func() *config.Config { return x.cfg })
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	h.enabled = true
	var journal strings.Builder
	for _, message := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		b, _ := json.Marshal(map[string]string{"_SYSTEMD_UNIT": "netos-xray-srv1.service", "_PID": "777", "MESSAGE": message})
		journal.Write(b)
		journal.WriteByte('\n')
	}
	h.readResourceJournal(context.Background(), strings.NewReader(journal.String()))
	if len(h.limits) != 0 {
		t.Fatal("diagnostic-only losses falsely mark resource history incomplete", h.limits)
	}
}

func TestXrayJournalWorkerKeepsResourcesAndRejectsForeignUnits(t *testing.T) {
	x, _ := resourceFixture()
	h, err := NewClientHistory(filepath.Join(t.TempDir(), "history.db"), nil, nil, func() *config.Config { return x.cfg })
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	h.enabled = true
	h.addresses["192.0.2.2"] = ClientCounter{ID: "lan-client", Address: "192.0.2.2"}
	entry := func(unit, message string) string {
		b, _ := json.Marshal(map[string]string{"_SYSTEMD_UNIT": unit, "_PID": "777", "_SYSTEMD_INVOCATION_ID": "invocation", "SYSLOG_IDENTIFIER": "netos-xray", "MESSAGE": message})
		return string(b) + "\n"
	}
	foreign := entry("other.service", "query[A] forged.example from 192.0.2.2") + entry("other.service", xraylog.LossPrefix+"10 messages (oversized=0, resources=10)")
	h.readResourceJournal(context.Background(), strings.NewReader(foreign))
	if len(h.resources) != 0 || len(h.dns) != 0 || len(h.limits) != 0 {
		t.Fatal("foreign identifier accepted")
	}
	message := resourceAccess("password.example", "a")
	if xraylog.Sanitize(message) != message {
		t.Fatal("resource target redacted as a credential")
	}
	input := entry("netos-xray-srv1.service", message) + entry("netos-xray-srv1.service", xraylog.LossPrefix+"10 messages (oversized=1, resources=10)")
	h.readResourceJournal(context.Background(), strings.NewReader(input))
	if len(h.resources) != 1 || len(h.limits) != 1 {
		t.Fatal("resource or loss missing", h.resources, h.limits)
	}
	for _, r := range h.resources {
		if r.Domain != "password.example" || r.Client != "vpn:s:a" || r.Count != 1 {
			t.Fatal(r)
		}
	}
}
