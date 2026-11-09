package api

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestDiagnosticAddressMessages(t *testing.T) {
	message := func(family byte, index uint32, attrs ...[]byte) syscall.NetlinkMessage {
		data := make([]byte, 8)
		data[0] = family
		binary.NativeEndian.PutUint32(data[4:], index)
		for _, a := range attrs {
			data = append(data, a...)
		}
		return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.RTM_NEWADDR}, Data: data}
	}
	attr := func(kind uint16, ip net.IP) []byte {
		a := make([]byte, (4+len(ip)+3)&^3)
		binary.NativeEndian.PutUint16(a, uint16(4+len(ip)))
		binary.NativeEndian.PutUint16(a[2:], kind)
		copy(a[4:], ip)
		return a
	}
	v4 := func(s string) []byte { return attr(syscall.IFA_ADDRESS, net.ParseIP(s).To4()) }
	local := attr(syscall.IFA_LOCAL, net.ParseIP("192.0.2.1").To4())
	messages := []syscall.NetlinkMessage{
		message(syscall.AF_INET, 2, v4("192.0.2.2"), local),
		message(syscall.AF_INET, 1, v4("127.0.0.1")),
		message(syscall.AF_INET, 2, v4("198.51.100.1")),
		message(syscall.AF_INET6, 2, attr(syscall.IFA_ADDRESS, net.ParseIP("2001:db8::1"))),
		message(syscall.AF_INET6, 2, attr(syscall.IFA_ADDRESS, net.ParseIP("::ffff:203.0.113.1"))),
	}
	got, err := diagnosticAddressMessages(messages)
	want := map[int][]string{1: {"127.0.0.1"}, 2: {"192.0.2.1", "198.51.100.1", "203.0.113.1"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, m := range []syscall.NetlinkMessage{
		{Header: syscall.NlMsghdr{Type: syscall.RTM_NEWADDR}},
		message(syscall.AF_INET, 2, []byte{3, 0, 1, 0}),
		message(syscall.AF_INET, 2, attr(syscall.IFA_ADDRESS, []byte{1})),
	} {
		if got, err := diagnosticAddressMessages([]syscall.NetlinkMessage{messages[0], m}); err == nil || got != nil {
			t.Fatalf("partial snapshot on error: %v, %v", got, err)
		}
	}
}

type diagnosticTestInterface struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

func diagnosticTestInterfaces(old bool) ([]diagnosticTestInterface, error) {
	list, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var addresses map[int][]string
	if !old {
		addresses, err = diagnosticAddresses()
		if err != nil {
			return nil, err
		}
	}
	result := []diagnosticTestInterface{}
	for _, item := range list {
		row := diagnosticTestInterface{Name: item.Name, Addresses: []string{}}
		if old {
			addrs, _ := item.Addrs()
			for _, a := range addrs {
				ip, _, _ := net.ParseCIDR(a.String())
				if ip.To4() != nil {
					row.Addresses = append(row.Addresses, ip.String())
				}
			}
		} else {
			row.Addresses = append(row.Addresses, addresses[item.Index]...)
		}
		result = append(result, row)
	}
	return result, nil
}

func TestDiagnosticAddressesNative(t *testing.T) {
	if os.Getenv("NETOS_TEST_INTERFACE_NAMESPACE") != "1" {
		t.Skip("requires isolated network namespace and ip")
	}
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	check := func() {
		t.Helper()
		want, err := diagnosticTestInterfaces(true)
		if err != nil {
			t.Fatal(err)
		}
		got, err := diagnosticTestInterfaces(false)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("snapshot differs: %v %v %v", got, want, err)
		}
		w := httptest.NewRecorder()
		(&Server{}).handleDiagnosticTools(w, httptest.NewRequest("GET", "/api/diagnostics/tools", nil))
		var response struct {
			Interfaces []diagnosticTestInterface `json:"interfaces"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != 200 || !reflect.DeepEqual(response.Interfaces, want) {
			t.Fatalf("handler differs: %s %v", w.Body, err)
		}
	}
	ip("link", "set", "lo", "up")
	check()
	ip("link", "add", "qa0", "type", "dummy")
	check()
	ip("address", "add", "192.0.2.1/24", "dev", "qa0")
	ip("address", "add", "192.0.2.2/24", "dev", "qa0")
	ip("address", "add", "2001:db8::1/64", "dev", "qa0")
	check()
	ip("address", "add", "198.51.100.1", "peer", "198.51.100.2", "dev", "qa0")
	check()
	ip("link", "set", "qa0", "name", "renamed")
	check()
	ip("address", "del", "192.0.2.1/24", "dev", "renamed")
	check()
	ip("link", "del", "renamed")
	check()
	last := 0
	for _, n := range []int{10, 100, 500} {
		var script strings.Builder
		for i := last; i < n; i++ {
			fmt.Fprintf(&script, "link add qa%d type dummy\naddress add 198.18.%d.%d/32 dev qa%d\n", i, i/250, i%250+1, i)
		}
		cmd := exec.Command("ip", "-batch", "-")
		cmd.Stdin = strings.NewReader(script.String())
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatal(err, string(out))
		}
		last = n
		check()
		for _, old := range []bool{true, false} {
			result := testing.Benchmark(func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					if _, err := diagnosticTestInterfaces(old); err != nil {
						b.Fatal(err)
					}
				}
			})
			t.Logf("interfaces=%d old=%t %s %s", n+1, old, result.String(), result.MemString())
		}
	}
}
