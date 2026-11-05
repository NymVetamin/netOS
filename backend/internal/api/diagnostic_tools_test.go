package api

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticValidation(t *testing.T) {
	for _, input := range []diagnosticInput{
		{Kind: "ping", Host: "--help"}, {Kind: "ping", Host: "example.org;id"},
		{Kind: "ping", Host: "example.org", Count: 31}, {Kind: "ping", Host: "example.org", Size: 65535},
		{Kind: "traceroute", Host: "example.org", TTL: 65}, {Kind: "mtr", Host: "example.org", Interface: "not-a-netos-interface"},
		{Kind: "dns", Host: "example.org", DNSServer: "@bad"}, {Kind: "dns", Host: "example.org", QueryType: "-f"},
		{Kind: "capture", Address: "invalid"}, {Kind: "torch", Direction: "invalid"}, {Kind: "iperf", Host: "127.0.0.1", Port: 22},
		{Kind: "iperf", Mode: "server"}, {Kind: "iperf", Mode: "server", Bind: "0.0.0.0"},
		{Kind: "iperf", Host: "127.0.0.1", Mbps: 10001}, {Kind: "route", Host: "example.org"}, {Kind: "shell"},
	} {
		if _, err := buildDiagnosticCommand(input); err == nil {
			t.Errorf("accepted %#v", input)
		}
	}
	for _, kind := range []string{"ping", "traceroute", "mtr", "dns", "iperf", "connections", "route"} {
		c, err := buildDiagnosticCommand(diagnosticInput{Kind: kind, Host: "127.0.0.1"})
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if c.duration <= 0 || c.duration > 75*time.Second {
			t.Fatal(c)
		}
	}
	c, err := buildDiagnosticCommand(diagnosticInput{Kind: "iperf", Host: "127.0.0.1", UDP: true, Reverse: true, Mbps: 20, Duration: 2})
	if err != nil || !strings.Contains(strings.Join(c.args, " "), "-b 20M") || c.args[len(c.args)-1] != "-R" {
		t.Fatal(c, err)
	}
}

func TestDiagnosticPermissionsAndOwnership(t *testing.T) {
	for _, level := range []string{"none", "view", "manage"} {
		for _, path := range []string{"/api/diagnostics/tools", "/api/diagnostics/current", "/api/diagnostics/jobs", "/api/diagnostics/jobs/id", "/api/diagnostics/jobs/id/capture"} {
			r := limitedRequest(map[string]string{"diagnostics": level})
			r.URL.Path = path
			want := level == "manage" || (path == "/api/diagnostics/tools" && level == "view")
			if limitedEndpoint(r) != want {
				t.Errorf("%s %s", level, path)
			}
		}
	}
	j := &diagnosticJob{id: "private", owner: "alice", kind: "capture", started: time.Now(), finished: time.Now(), state: "done"}
	j.pcap, _ = os.Create(filepath.Join(t.TempDir(), "test.pcap"))
	j.pcap.Write(pcapFixture(1, 1))
	j.captureBytes = int64(len(pcapFixture(1, 1)))
	j.pcap.Close()
	s := &Server{diagnostics: diagnosticManager{jobs: map[string]*diagnosticJob{j.id: j}}}
	for _, handler := range []func(*httptest.ResponseRecorder){
		func(w *httptest.ResponseRecorder) {
			r := httptest.NewRequest("GET", "/", nil)
			r.SetPathValue("id", j.id)
			s.handleDiagnosticJob(w, r)
		},
		func(w *httptest.ResponseRecorder) {
			r := httptest.NewRequest("GET", "/", nil)
			r.SetPathValue("id", j.id)
			s.handleDiagnosticCapture(w, r)
		},
		func(w *httptest.ResponseRecorder) {
			r := httptest.NewRequest("DELETE", "/", nil)
			r.SetPathValue("id", j.id)
			s.handleDiagnosticStop(w, r)
		},
	} {
		w := httptest.NewRecorder()
		handler(w)
		if w.Code != 404 {
			t.Fatal(w.Code)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(context.WithValue(r.Context(), ctxUser, "alice"))
	r.SetPathValue("id", j.id)
	w := httptest.NewRecorder()
	s.handleDiagnosticCapture(w, r)
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), pcapFixture(1, 1)) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestDiagnosticLegacyProbeSharesLimit(t *testing.T) {
	s := &Server{diagnostics: diagnosticManager{active: true}}
	w := httptest.NewRecorder()
	s.handleDiagnosticProbe(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"kind":"ping","host":"127.0.0.1"}`)))
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestDiagnosticOutputLimitsAndStop(t *testing.T) {
	cancelled := false
	j := &diagnosticJob{state: "running", cancel: func() { cancelled = true }}
	w := diagnosticWriter{job: j}
	p := bytes.Repeat([]byte("a"), diagnosticTextLimit+100)
	if n, err := w.Write(p); n != len(p) || err != nil {
		t.Fatal(n, err)
	}
	if j.output.Len() != diagnosticTextLimit || !j.truncated {
		t.Fatal("text unbounded")
	}
	j.truncated = false
	j.pcap, _ = os.Create(filepath.Join(t.TempDir(), "large.pcap"))
	recorder := &capturePacketWriter{job: j}
	fixture := pcapFixture(1, 10000)
	recorder.Write(fixture)
	for i := 0; i < 20; i++ {
		if _, err := recorder.Write(fixture[24:]); err != nil {
			t.Fatal(err)
		}
	}
	if j.captureBytes <= 8<<20 || j.truncated || cancelled {
		t.Fatal("capture unexpectedly limited", j.captureBytes)
	}
	j.pcap.Close()
	for _, cut := range []int{0, 4, 23, 24, 25, 39, 40, 65, 81} {
		full := pcapFixture(1, 2)
		got := completePCAP(full[:cut])
		if len(got) > cut || (len(got) > 0 && pcapOrder(got) == nil) {
			t.Fatal(cut, len(got))
		}
	}
	j = &diagnosticJob{state: "running", torch: newTorchReader(), cancel: func() { cancelled = true }}
	_, err := (diagnosticWriter{job: j, binary: true}).Write(bytes.Repeat([]byte{0}, 24))
	if err == nil || j.state != "error" || j.failure == "" {
		t.Fatal("invalid PCAP not reported")
	}
}

// Ethernet IPv4/UDP fixture; a distinct source port identifies each flow.
func pcapFixture(link uint32, packets int) []byte {
	var b bytes.Buffer
	header := make([]byte, 24)
	copy(header, []byte{0xd4, 0xc3, 0xb2, 0xa1})
	binary.LittleEndian.PutUint16(header[4:], 2)
	binary.LittleEndian.PutUint16(header[6:], 4)
	binary.LittleEndian.PutUint32(header[16:], 65535)
	binary.LittleEndian.PutUint32(header[20:], link)
	b.Write(header)
	for i := 0; i < packets; i++ {
		offset := 0
		switch link {
		case 1:
			offset = 14
		case 113:
			offset = 16
		case 276:
			offset = 20
		}
		packet := make([]byte, offset+28)
		switch link {
		case 1:
			binary.BigEndian.PutUint16(packet[12:], 0x800)
		case 113:
			binary.BigEndian.PutUint16(packet[14:], 0x800)
		case 276:
			binary.BigEndian.PutUint16(packet, 0x800)
		}
		ip := packet[offset:]
		ip[0] = 0x45
		ip[9] = 17
		copy(ip[12:], []byte{192, 0, 2, 1})
		copy(ip[16:], []byte{192, 0, 2, 2})
		binary.BigEndian.PutUint16(ip[20:], uint16(i+1024))
		binary.BigEndian.PutUint16(ip[22:], 53)
		record := make([]byte, 16)
		binary.LittleEndian.PutUint32(record[8:], uint32(len(packet)))
		binary.LittleEndian.PutUint32(record[12:], uint32(len(packet)))
		b.Write(record)
		b.Write(packet)
	}
	return b.Bytes()
}

func TestDiagnosticTorchStreaming(t *testing.T) {
	for _, link := range []uint32{1, 101, 113, 276} {
		data := pcapFixture(link, 10)
		for _, chunk := range []int{1, 17, len(data)} {
			r := newTorchReader()
			for at := 0; at < len(data); at += chunk {
				end := at + chunk
				if end > len(data) {
					end = len(data)
				}
				if _, err := r.Write(data[at:end]); err != nil {
					t.Fatal(err)
				}
			}
			if len(r.flows) != 10 || r.packets != 10 || r.skipped != 0 || len(r.pending) != 0 {
				t.Fatalf("link %d: %#v", link, r)
			}
			rows := r.snapshot(2)["flows"].([]torchFlow)
			if rows[0].Source != "192.0.2.1" || rows[0].DestinationPort != 53 || rows[0].Protocol != "UDP" || rows[0].Bitrate != float64(rows[0].Bytes)*4 {
				t.Fatal(rows[0])
			}
		}
	}
	r := newTorchReader()
	if _, err := r.Write(pcapFixture(1, 10000)); err != nil {
		t.Fatal(err)
	}
	if len(r.flows) != 10000 || r.skipped != 0 || len(r.snapshot(1)["flows"].([]torchFlow)) != 10000 {
		t.Fatal("flow limit failed")
	}
	if rows := r.snapshot(1, 25)["flows"].([]torchFlow); len(rows) != 100 {
		t.Fatal("page lost flows")
	}
	// VLAN header and non-initial fragment: preserve addresses, never invent ports.
	r = newTorchReader()
	r.link = 1
	p := pcapFixture(1, 1)[40:]
	vlan := append([]byte(nil), p[:12]...)
	vlan = append(vlan, 0x81, 0, 0, 1)
	vlan = append(vlan, p[12:]...)
	r.packet(vlan, uint32(len(vlan)))
	if len(r.flows) != 1 {
		t.Fatal("VLAN lost")
	}
	p = append([]byte(nil), p...)
	p[20], p[21] = 0, 1
	r.packet(p, uint32(len(p)))
	if len(r.flows) != 2 {
		t.Fatal("fragment conflated with UDP ports")
	}
}

func BenchmarkDiagnosticTorch(b *testing.B) {
	for _, packets := range []int{100, 10000} {
		b.Run(strconv.Itoa(packets)+"_packets", func(b *testing.B) {
			data := pcapFixture(1, packets)
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r := newTorchReader()
				for at := 0; at < len(data); at += 32768 {
					end := at + 32768
					if end > len(data) {
						end = len(data)
					}
					_, _ = r.Write(data[at:end])
				}
				r.snapshot(10)
			}
		})
	}
}
