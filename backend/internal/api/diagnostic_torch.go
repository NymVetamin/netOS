package api

import (
	"encoding/binary"
	"errors"
	"net"
	"sort"
)

type torchFlow struct {
	Source          string  `json:"source"`
	Destination     string  `json:"destination"`
	Protocol        string  `json:"protocol"`
	SourcePort      uint16  `json:"source_port"`
	DestinationPort uint16  `json:"destination_port"`
	Packets         uint64  `json:"packets"`
	Bytes           uint64  `json:"bytes"`
	Bitrate         float64 `json:"bitrate"`
}
type torchKey struct {
	source, destination         [4]byte
	protocol                    byte
	sourcePort, destinationPort uint16
}
type torchReader struct {
	pending          []byte
	order            binary.ByteOrder
	link             uint32
	flows            map[torchKey]*torchFlow
	packets, skipped uint64
}

func newTorchReader() *torchReader { return &torchReader{flows: make(map[torchKey]*torchFlow)} }

func pcapOrder(data []byte) binary.ByteOrder {
	if len(data) < 24 {
		return nil
	}
	switch string(data[:4]) {
	case "\xd4\xc3\xb2\xa1", "\x4d\x3c\xb2\xa1":
		return binary.LittleEndian
	case "\xa1\xb2\xc3\xd4", "\xa1\xb2\x3c\x4d":
		return binary.BigEndian
	}
	return nil
}
func completePCAP(data []byte) []byte {
	order := pcapOrder(data)
	if order == nil {
		return nil
	}
	at := 24
	for at+16 <= len(data) {
		n := int(order.Uint32(data[at+8 : at+12]))
		if n > 65535 || at+16+n > len(data) {
			break
		}
		at += 16 + n
	}
	return data[:at]
}

// Streaming parser holds only one incomplete packet and a capped flow map.
// It never retains payloads once their headers have been counted.
func (t *torchReader) Write(data []byte) (int, error) {
	n := len(data)
	t.pending = append(t.pending, data...)
	if t.order == nil {
		if len(t.pending) < 24 {
			return n, nil
		}
		t.order = pcapOrder(t.pending)
		if t.order == nil {
			return 0, errors.New("неподдерживаемый формат PCAP")
		}
		t.link = t.order.Uint32(t.pending[20:24]) & 0xffff
		switch t.link {
		case 1, 101, 113, 276:
		default:
			return 0, errors.New("тип интерфейса не поддерживает Torch")
		}
		t.pending = t.pending[24:]
	}
	at := 0
	for at+16 <= len(t.pending) {
		length := int(t.order.Uint32(t.pending[at+8 : at+12]))
		if length > 65535 {
			return 0, errors.New("повреждённый пакет PCAP")
		}
		if at+16+length > len(t.pending) {
			break
		}
		wire := t.order.Uint32(t.pending[at+12 : at+16])
		t.packet(t.pending[at+16:at+16+length], wire)
		at += 16 + length
	}
	copy(t.pending, t.pending[at:])
	t.pending = t.pending[:len(t.pending)-at]
	return n, nil
}
func (t *torchReader) packet(p []byte, wire uint32) {
	t.packets++
	offset := 0
	ether := uint16(0x0800)
	switch t.link {
	case 1:
		if len(p) < 14 {
			t.skipped++
			return
		}
		ether = binary.BigEndian.Uint16(p[12:14])
		offset = 14
	case 113:
		if len(p) < 16 {
			t.skipped++
			return
		}
		ether = binary.BigEndian.Uint16(p[14:16])
		offset = 16
	case 276:
		if len(p) < 20 {
			t.skipped++
			return
		}
		ether = binary.BigEndian.Uint16(p[:2])
		offset = 20
	}
	for depth := 0; depth < 2 && (ether == 0x8100 || ether == 0x88a8); depth++ {
		if len(p) < offset+4 {
			t.skipped++
			return
		}
		ether = binary.BigEndian.Uint16(p[offset+2 : offset+4])
		offset += 4
	}
	if ether != 0x0800 || len(p) < offset+20 {
		t.skipped++
		return
	}
	p = p[offset:]
	header := int(p[0]&15) * 4
	if p[0]>>4 != 4 || header < 20 || len(p) < header {
		t.skipped++
		return
	}
	k := torchKey{protocol: p[9]}
	copy(k.source[:], p[12:16])
	copy(k.destination[:], p[16:20])
	// Non-initial IP fragments do not contain transport ports.
	if (k.protocol == 6 || k.protocol == 17) && binary.BigEndian.Uint16(p[6:8])&0x1fff == 0 && len(p) >= header+4 {
		k.sourcePort = binary.BigEndian.Uint16(p[header : header+2])
		k.destinationPort = binary.BigEndian.Uint16(p[header+2 : header+4])
	}
	f := t.flows[k]
	if f == nil {
		if len(t.flows) >= 2048 {
			t.skipped++
			return
		}
		protocol := "IP"
		switch k.protocol {
		case 6:
			protocol = "TCP"
		case 17:
			protocol = "UDP"
		case 1:
			protocol = "ICMP"
		case 47:
			protocol = "GRE"
		case 50:
			protocol = "ESP"
		}
		f = &torchFlow{Source: net.IP(k.source[:]).String(), Destination: net.IP(k.destination[:]).String(), Protocol: protocol, SourcePort: k.sourcePort, DestinationPort: k.destinationPort}
		t.flows[k] = f
	}
	f.Packets++
	f.Bytes += uint64(wire)
}
func (t *torchReader) snapshot(seconds float64) map[string]any {
	rows := make([]torchFlow, 0, len(t.flows))
	for _, f := range t.flows {
		row := *f
		if seconds > 0 {
			row.Bitrate = float64(row.Bytes) * 8 / seconds
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Bytes != rows[j].Bytes {
			return rows[i].Bytes > rows[j].Bytes
		}
		if rows[i].Source != rows[j].Source {
			return rows[i].Source < rows[j].Source
		}
		if rows[i].Destination != rows[j].Destination {
			return rows[i].Destination < rows[j].Destination
		}
		if rows[i].Protocol != rows[j].Protocol {
			return rows[i].Protocol < rows[j].Protocol
		}
		if rows[i].SourcePort != rows[j].SourcePort {
			return rows[i].SourcePort < rows[j].SourcePort
		}
		return rows[i].DestinationPort < rows[j].DestinationPort
	})
	if len(rows) > 200 {
		rows = rows[:200]
	}
	return map[string]any{"flows": rows, "total_flows": len(t.flows), "packets": t.packets, "skipped": t.skipped}
}
