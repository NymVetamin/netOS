package api

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Structured fields are compiled into one BPF argument, never shell text.
func buildCaptureCommand(in diagnosticInput) (diagnosticCommand, error) {
	c := diagnosticCommand{name: "tcpdump"}
	bad := func(s string) (diagnosticCommand, error) { return c, errors.New(s) }
	match := ""
	switch in.Match {
	case "", "either":
	case "src", "dst":
		match = in.Match + " "
	default:
		return bad("неизвестное направление адресного фильтра")
	}
	parts := []string{}
	if in.Address != "" {
		if net.ParseIP(in.Address) != nil {
			parts = append(parts, match+"host "+in.Address)
		} else if _, _, err := net.ParseCIDR(in.Address); err == nil {
			parts = append(parts, match+"net "+in.Address)
		} else {
			return bad("укажите IP-адрес или подсеть CIDR")
		}
	}
	if in.MAC != "" {
		mac, err := net.ParseMAC(in.MAC)
		if err != nil || len(mac) != 6 {
			return bad("некорректный MAC-адрес")
		}
		parts = append(parts, "ether "+match+"host "+mac.String())
	}
	switch in.Protocol {
	case "", "any":
	case "tcp", "udp", "icmp", "icmp6", "arp", "ip", "ip6":
		parts = append(parts, in.Protocol)
	default:
		return bad("неподдерживаемый протокол")
	}
	if in.Ports != "" {
		if in.Protocol != "" && in.Protocol != "any" && in.Protocol != "tcp" && in.Protocol != "udp" {
			return bad("фильтр портов применяется к TCP/UDP")
		}
		ports := []string{}
		for _, item := range strings.Split(in.Ports, ",") {
			bounds := strings.Split(strings.TrimSpace(item), "-")
			if len(bounds) > 2 {
				return bad("укажите порты через запятую или диапазон 1000-2000")
			}
			numbers := []int{}
			for _, bound := range bounds {
				n, err := strconv.Atoi(bound)
				if err != nil || n < 1 || n > 65535 {
					return bad("порт должен быть от 1 до 65535")
				}
				numbers = append(numbers, n)
			}
			if len(numbers) == 2 {
				if numbers[0] > numbers[1] {
					return bad("начало диапазона портов больше конца")
				}
				ports = append(ports, match+"portrange "+strconv.Itoa(numbers[0])+"-"+strconv.Itoa(numbers[1]))
			} else {
				ports = append(ports, match+"port "+strconv.Itoa(numbers[0]))
			}
		}
		parts = append(parts, "(tcp or udp) and ("+strings.Join(ports, " or ")+")")
	}
	if strings.ContainsAny(in.Filter, "\x00\r\n") {
		return bad("фильтр BPF должен быть одной строкой")
	}
	if in.Filter != "" {
		parts = append(parts, in.Filter)
	}
	for i := range parts {
		parts[i] = "(" + parts[i] + ")"
	}
	iface := in.Interface
	if iface == "" {
		iface = "any"
	}
	if iface != "any" {
		if _, err := net.InterfaceByName(iface); err != nil {
			return bad("интерфейс не найден")
		}
	}
	c.interfaces = []string{iface}
	// Linux cooked headers do not retain both Ethernet addresses. For a MAC
	// filter capture native Ethernet on every eligible interface instead.
	if iface == "any" && in.MAC != "" {
		list, err := net.Interfaces()
		if err != nil {
			return c, err
		}
		c.interfaces = nil
		for _, item := range list {
			if len(item.HardwareAddr) == 6 && item.Flags&net.FlagUp != 0 {
				c.interfaces = append(c.interfaces, item.Name)
			}
		}
		if len(c.interfaces) == 0 {
			return bad("нет активных Ethernet-интерфейсов для MAC-фильтра")
		}
	}
	c.args = []string{"-n", "-p", "-U", "--immediate-mode", "-i", iface, "-s", "0", "-w", "-"}
	if in.MAC != "" {
		c.args = append(c.args, "-y", "EN10MB")
	}
	switch in.Direction {
	case "", "inout":
	case "in", "out":
		c.args = append(c.args, "-Q", in.Direction)
	default:
		return bad("направление захвата: in, out или inout")
	}
	c.args = append(c.args, "--")
	if len(parts) > 0 {
		c.args = append(c.args, strings.Join(parts, " and "))
	}
	return c, nil
}

func runCapture(ctx context.Context, path string, command diagnosticCommand, j *diagnosticJob) error {
	var wg sync.WaitGroup
	var first error
	var mu sync.Mutex
	for _, iface := range command.interfaces {
		args := append([]string(nil), command.args...)
		for i := range args {
			if args[i] == "-i" {
				args[i+1] = iface
				break
			}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.CommandContext(ctx, path, args...)
			cmd.Stdout = &capturePacketWriter{job: j}
			cmd.Stderr = diagnosticWriter{job: j}
			cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
			cmd.WaitDelay = 2 * time.Second
			if err := cmd.Run(); err != nil && ctx.Err() == nil {
				mu.Lock()
				if first == nil {
					first = fmt.Errorf("%s: %w", iface, err)
				}
				mu.Unlock()
				j.mu.Lock()
				j.state = "error"
				j.failure = first.Error()
				j.cancel()
				j.mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return first
}

// Keep at most an incomplete record between writes. Complete records go straight
// to disk or Torch; no payload accumulation proportional to capture duration.
type capturePacketWriter struct {
	job             *diagnosticJob
	pending, header []byte
	order           binary.ByteOrder
}

func (w *capturePacketWriter) Write(p []byte) (int, error) {
	n := len(p)
	w.pending = append(w.pending, p...)
	if w.order == nil {
		if len(w.pending) < 24 {
			return n, nil
		}
		w.order = pcapOrder(w.pending)
		if w.order == nil {
			return 0, errors.New("неподдерживаемый PCAP")
		}
		w.header = append([]byte(nil), w.pending[:24]...)
		w.pending = w.pending[24:]
	}
	at := 0
	j := w.job
	j.mu.Lock()
	defer j.mu.Unlock()
	fail := func(err error) (int, error) { j.state = "error"; j.failure = err.Error(); j.cancel(); return 0, err }
	if j.pcap != nil && j.captureBytes == 0 {
		if _, err := j.pcap.Write(w.header); err != nil {
			return fail(err)
		}
		j.captureHeader = append([]byte(nil), w.header...)
		j.captureBytes = 24
	}
	if j.pcap != nil && !bytes.Equal(j.captureHeader, w.header) {
		return fail(errors.New("несовместимые заголовки PCAP интерфейсов"))
	}
	for at+16 <= len(w.pending) {
		size := uint64(w.order.Uint32(w.pending[at+8 : at+12]))
		if size > uint64(w.order.Uint32(w.header[16:20])) {
			return fail(errors.New("повреждённая длина пакета PCAP"))
		}
		if size > uint64(len(w.pending)-at-16) {
			break
		}
		end := at + 16 + int(size)
		if j.torch != nil {
			j.torch.link = w.order.Uint32(w.header[20:24]) & 0xffff
			j.torch.packet(w.pending[at+16:end], w.order.Uint32(w.pending[at+12:at+16]))

		}
		at = end
	}
	if j.pcap != nil && at > 0 {
		written, err := j.pcap.Write(w.pending[:at])
		if err != nil {
			_ = j.pcap.Truncate(j.captureBytes)
			return fail(err)
		}
		j.captureBytes += int64(written)
	}
	copy(w.pending, w.pending[at:])
	w.pending = w.pending[:len(w.pending)-at]
	return n, nil
}
