package api

import (
	"fmt"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

const trackedSample = "ipv4 2 tcp 6 120 ESTABLISHED src=192.0.2.10 dst=198.51.100.2 sport=45000 dport=443 packets=12 bytes=1200 src=198.51.100.2 dst=203.0.113.1 sport=443 dport=55000 packets=9 bytes=900 [ASSURED] mark=0 use=1"

func TestConnectionParsers(t *testing.T) {
	c, ok := parseTrackedConnection(trackedSample)
	if !ok || c.NAT != "SNAT" || c.Source.Address != "192.0.2.10" || *c.Bytes != 1200 || *c.ReplyPackets != 9 || c.State != "ESTABLISHED" {
		t.Fatal(c, ok)
	}
	v6 := "ipv6 10 udp 17 29 src=2001:db8::1 dst=2001:db8::2 sport=1234 dport=53 [UNREPLIED] src=2001:db8::2 dst=2001:db8::1 sport=53 dport=1234 mark=0 use=1"
	c, ok = parseTrackedConnection(v6)
	if !ok || c.NAT != "" || c.State != "UNREPLIED" || c.Bytes != nil {
		t.Fatal(c, ok)
	}
	dnat := "tcp 6 60 ESTABLISHED src=192.0.2.10 dst=203.0.113.1 sport=40000 dport=443 src=10.0.0.2 dst=192.0.2.10 sport=8443 dport=40000"
	c, ok = parseTrackedConnection(dnat)
	if !ok || c.NAT != "DNAT" {
		t.Fatal(c, ok)
	}
	c, ok = parseSocketConnection(`tcp ESTAB 0 0 [::ffff:192.0.2.10]:22 [::ffff:198.51.100.2]:50000 users:(("sshd",pid=100,fd=3))`)
	if !ok || c.Source.Port != "22" || c.Source.Address != "::ffff:192.0.2.10" || !strings.Contains(c.Process, "sshd") {
		t.Fatal(c, ok)
	}
	for _, line := range []string{"", "broken", "ipv4 2 tcp 6 10 src=x dst=y"} {
		if _, ok := parseTrackedConnection(line); ok {
			t.Fatal(line)
		}
	}
}
func TestConnectionFiltersAndPagination(t *testing.T) {
	c, _ := parseTrackedConnection(trackedSample)
	for query, want := range map[string]bool{
		"address=192.0.2.0/24": true, "address=203.0.113.1": true, "address=203.0.113.1&side=src": false,
		"ports=53,440-450&side=dst": true, "ports=45000&side=src": true, "ports=55000": true,
		"protocol=UDP": false, "protocol=TCP&state=ESTAB&nat=SNAT": true, "nat=no": false,
		"ports=100-200,150-250,443,600": true,
	} {
		f, err := parseConnectionFilter(httptest.NewRequest("GET", "/?"+query, nil))
		if err != nil || f.matches(c) != want {
			t.Fatal(query, err)
		}
	}
	for _, query := range []string{"address=invalid", "ports=0", "ports=200-100", "ports=65536", "nat=invalid", "side=invalid"} {
		if _, err := parseConnectionFilter(httptest.NewRequest("GET", "/?"+query, nil)); err == nil {
			t.Fatal(query)
		}
	}
	page := connectionPage{Page: 1}
	if err := scanConnectionRows(strings.NewReader(strings.Repeat(trackedSample+"\n", 250)), parseTrackedConnection, connectionFilter{}, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 100 || page.Total != 250 || page.Scanned != 250 {
		t.Fatal(page.Total, page.Scanned, len(page.Rows))
	}
	page = connectionPage{}
	scanConnectionRows(strings.NewReader("invalid\n"+trackedSample), parseTrackedConnection, connectionFilter{}, &page)
	if page.Unparsed != 1 || page.Total != 1 {
		t.Fatal(page)
	}
	for _, level := range []string{"none", "view", "manage"} {
		r := limitedRequest(map[string]string{"diagnostics": level})
		r.URL.Path = "/api/diagnostics/connections"
		if limitedEndpoint(r) != (level != "none") {
			t.Fatal(level)
		}
	}
}
func BenchmarkConnectionPage(b *testing.B) {
	for _, size := range []int{1000, 100000} {
		data := strings.Repeat(trackedSample+"\n", size)
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			for i := 0; i < b.N; i++ {
				page := connectionPage{Page: 3}
				if err := scanConnectionRows(strings.NewReader(data), parseTrackedConnection, connectionFilter{}, &page); err != nil {
					b.Fatal(err)
				}
				if page.Total != size {
					b.Fatal(fmt.Sprint(page.Total))
				}
			}
		})
	}
}
