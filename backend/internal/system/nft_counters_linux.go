//go:build linux

package system

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

// NFTSetCounters reads the four existing accounting sets without resetting them.
// A ruleset generation change invalidates the whole sample, including all sets.
func (e *Exec) NFTSetCounters(ctx context.Context, table string) (map[string]map[string]uint64, error) {
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	generation := func() (uint32, error) {
		messages, err := kernelDump(ctx, unix.NETLINK_NETFILTER, nftReadRequest(16, nil))
		if err != nil {
			return 0, err
		}
		if len(messages) != 1 || len(messages[0].Data) < 4 {
			return 0, fmt.Errorf("missing nft generation")
		}
		attrs, err := nftAttrs(messages[0].Data[4:])
		if err != nil {
			return 0, err
		}
		if len(attrs[1]) != 1 || len(attrs[1][0]) != 4 {
			return 0, fmt.Errorf("invalid nft generation")
		}
		return binary.BigEndian.Uint32(attrs[1][0]), nil
	}
	before, err := generation()
	if err != nil {
		return nil, err
	}
	result := map[string]map[string]uint64{}
	for _, name := range []string{"up4", "down4", "up6", "down6"} {
		payload := append(nftAttr(1, append([]byte(table), 0)), nftAttr(2, append([]byte(name), 0))...)
		messages, err := kernelDump(ctx, unix.NETLINK_NETFILTER, nftReadRequest(13, payload))
		if err != nil {
			return nil, err
		}
		counts := map[string]uint64{}
		for _, m := range messages {
			if m.Header.Type != 0xa0c || len(m.Data) < 4 {
				return nil, fmt.Errorf("unexpected nft elements response")
			}
			if err := parseNFTCounters(m.Data[4:], counts); err != nil {
				return nil, err
			}
		}
		result[name] = counts
	}
	after, err := generation()
	if err != nil {
		return nil, err
	}
	if before != after {
		return nil, fmt.Errorf("nft ruleset changed during sample")
	}
	return result, nil
}

func nftReadRequest(kind uint16, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], 0xa00|kind)
	binary.NativeEndian.PutUint16(b[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	if kind == 16 { // GETGEN is a single response, followed by the requested ACK.
		binary.NativeEndian.PutUint16(b[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	}
	binary.NativeEndian.PutUint32(b[8:], 1)
	b[16] = unix.NFPROTO_INET
	copy(b[20:], payload)
	return b
}
func nftAttr(kind uint16, value []byte) []byte {
	n := 4 + len(value)
	b := make([]byte, (n+3)&^3)
	binary.NativeEndian.PutUint16(b, uint16(n))
	binary.NativeEndian.PutUint16(b[2:], kind)
	copy(b[4:], value)
	return b
}
func nftAttrs(b []byte) (map[uint16][][]byte, error) {
	a := map[uint16][][]byte{}
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, fmt.Errorf("short nft attribute")
		}
		n := int(binary.NativeEndian.Uint16(b))
		aligned := (n + 3) &^ 3
		if n < 4 || n > len(b) || aligned > len(b) {
			return nil, fmt.Errorf("invalid nft attribute length")
		}
		kind := binary.NativeEndian.Uint16(b[2:]) & 0x3fff
		a[kind] = append(a[kind], b[4:n])
		b = b[aligned:]
	}
	return a, nil
}
func parseNFTCounters(data []byte, counts map[string]uint64) error {
	attrs, err := nftAttrs(data)
	if err != nil {
		return err
	}
	for _, list := range attrs[3] {
		elements, err := nftAttrs(list)
		if err != nil {
			return err
		}
		for _, items := range elements {
			for _, item := range items {
				elem, err := nftAttrs(item)
				if err != nil {
					return err
				}
				if len(elem[1]) != 1 {
					return fmt.Errorf("missing nft key")
				}
				key, err := nftAttrs(elem[1][0])
				if err != nil {
					return err
				}
				if len(key[1]) != 1 {
					return fmt.Errorf("invalid nft key")
				}
				address, ok := netip.AddrFromSlice(key[1][0])
				if !ok {
					return fmt.Errorf("invalid nft address")
				}
				expressions := elem[7]
				for _, list := range elem[11] {
					nested, err := nftAttrs(list)
					if err != nil {
						return err
					}
					for _, items := range nested {
						expressions = append(expressions, items...)
					}
				}
				var value uint64
				for _, expr := range expressions {
					a, err := nftAttrs(expr)
					if err != nil {
						return err
					}
					if len(a[1]) != 1 || string(a[1][0]) != "counter\x00" {
						continue
					}
					if len(a[2]) != 1 {
						return fmt.Errorf("missing counter data")
					}
					c, err := nftAttrs(a[2][0])
					if err != nil {
						return err
					}
					if len(c[1]) != 1 || len(c[1][0]) != 8 {
						return fmt.Errorf("invalid counter value")
					}
					value = binary.BigEndian.Uint64(c[1][0])
				}
				counts[address.String()] = value
			}
		}
	}
	return nil
}
