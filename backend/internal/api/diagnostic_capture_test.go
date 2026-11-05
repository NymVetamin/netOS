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

func TestCaptureFiltersAndUnlimited(t *testing.T) {
	for _, kind := range []string{"capture", "torch"} {
		c, err := buildDiagnosticCommand(diagnosticInput{Kind: kind, Address: "192.0.2.0/24", Protocol: "udp", Ports: "53,1000-2000", Match: "dst", Direction: "out", Duration: 1, Count: 1, Size: 64})
		if err != nil {
			t.Fatal(err)
		}
		args := strings.Join(c.args, " ")
		for _, want := range []string{"-i any", "-s 0", "-Q out", "dst net 192.0.2.0/24", "dst port 53", "dst portrange 1000-2000", "(udp)"} {
			if !strings.Contains(args, want) {
				t.Fatal(args, want)
			}
		}
		if c.duration != 0 || strings.Contains(args, "-c ") {
			t.Fatal("implicit limit", c)
		}
	}
	for _, in := range []diagnosticInput{{Address: "-w file"}, {MAC: "invalid"}, {Protocol: "udp;id"}, {Ports: "0"}, {Ports: "65536"}, {Ports: "20-10"}, {Protocol: "icmp", Ports: "80"}, {Match: "invalid"}, {Direction: "bad"}, {Filter: "\n"}} {
		in.Kind = "capture"
		if _, err := buildDiagnosticCommand(in); err == nil {
			t.Fatal(in)
		}
	}
}

func TestCaptureRecordsFailureAndDownload(t *testing.T) {
	data := pcapFixture(1, 3)
	for _, chunk := range []int{1, 17, len(data)} {
		f, err := os.Create(filepath.Join(t.TempDir(), "capture.pcap"))
		if err != nil {
			t.Fatal(err)
		}
		j := &diagnosticJob{pcap: f, cancel: func() {}, kind: "capture", state: "done", finished: time.Now()}
		w := &capturePacketWriter{job: j}
		// A partial last record is never placed in the download.
		partial := data[:len(data)-1]
		for at := 0; at < len(partial); at += chunk {
			end := min(at+chunk, len(partial))
			if _, err := w.Write(partial[at:end]); err != nil {
				t.Fatal(err)
			}
		}
		f.Close()
		got, _ := os.ReadFile(f.Name())
		if !bytes.Equal(got, completePCAP(partial)) {
			t.Fatal("partial packet retained")
		}
		// Another interface writes complete records, not another global header.
		j.pcap, _ = os.OpenFile(f.Name(), os.O_WRONLY|os.O_APPEND, 0600)
		w2 := &capturePacketWriter{job: j}
		if _, err := w2.Write(data); err != nil {
			t.Fatal(err)
		}
		j.pcap.Close()
		got, _ = os.ReadFile(f.Name())
		if len(got) != len(completePCAP(partial))+len(data)-24 {
			t.Fatal("bad merge")
		}
		stopped := false
		j.cancel = func() { stopped = true }
		if _, err := w2.Write(data[24:]); err == nil || !stopped || j.state != "error" {
			t.Fatal("disk error ignored")
		}
		j.cleanup()
		if _, err := os.Stat(f.Name()); !os.IsNotExist(err) {
			t.Fatal("file leaked")
		}
	}
}

func TestCaptureCurrentOwnership(t *testing.T) {
	s := &Server{diagnostics: diagnosticManager{jobs: map[string]*diagnosticJob{
		"a": {id: "a", owner: "alice", kind: "capture", state: "running", started: time.Now()},
	}}}
	for _, user := range []string{"alice", "bob"} {
		r := httptest.NewRequest("GET", "/api/diagnostics/current?kind=capture", nil).WithContext(context.WithValue(context.Background(), ctxUser, user))
		w := httptest.NewRecorder()
		s.handleDiagnosticCurrent(w, r)
		if strings.Contains(w.Body.String(), `"id":"a"`) != (user == "alice") {
			t.Fatal(w.Body.String())
		}
	}
}

func TestTorchIPv6AndARP(t *testing.T) {
	p := make([]byte, 48)
	p[0] = 0x60
	p[6] = 17
	p[8] = 0x20
	p[9] = 1
	p[24] = 0x20
	p[25] = 1
	p[39] = 2
	binary.BigEndian.PutUint16(p[40:], 1234)
	binary.BigEndian.PutUint16(p[42:], 53)
	k, ok := torchPacketKey(0x86dd, p)
	if !ok || !k.source.Is6() || k.destinationPort != 53 {
		t.Fatal(k, ok)
	}
	arp := make([]byte, 28)
	arp[2] = 8
	arp[4] = 6
	arp[5] = 4
	copy(arp[14:18], []byte{192, 0, 2, 1})
	copy(arp[24:28], []byte{192, 0, 2, 2})
	k, ok = torchPacketKey(0x806, arp)
	if !ok || k.source.String() != "192.0.2.1" {
		t.Fatal(k, ok)
	}
}

func BenchmarkCaptureFileStreaming(b *testing.B) {
	for _, packets := range []int{100, 10000} {
		data := pcapFixture(1, packets)
		b.Run(strconv.Itoa(packets), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			for i := 0; i < b.N; i++ {
				f, _ := os.Create(filepath.Join(b.TempDir(), "capture"))
				j := &diagnosticJob{pcap: f, cancel: func() {}}
				w := &capturePacketWriter{job: j}
				for at := 0; at < len(data); at += 32768 {
					w.Write(data[at:min(at+32768, len(data))])
				}
				j.cleanup()
			}
		})
	}
}
