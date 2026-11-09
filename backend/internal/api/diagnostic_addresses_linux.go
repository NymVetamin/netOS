package api

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

// One fresh address dump avoids Interface.Addrs repeating the full Linux dump
// for every interface. The caller retains the old path if this snapshot fails.
func diagnosticAddresses() (map[int][]string, error) {
	data, err := syscall.NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	messages, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return nil, err
	}
	return diagnosticAddressMessages(messages)
}

func diagnosticAddressMessages(messages []syscall.NetlinkMessage) (map[int][]string, error) {
	addresses := make(map[int][]string)
	for _, m := range messages {
		if m.Header.Type == syscall.NLMSG_DONE {
			break
		}
		if m.Header.Type != syscall.RTM_NEWADDR {
			continue
		}
		if len(m.Data) < syscall.SizeofIfAddrmsg {
			return nil, fmt.Errorf("short interface address")
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			return nil, err
		}
		var address, local []byte
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case syscall.IFA_ADDRESS:
				address = attr.Value
			case syscall.IFA_LOCAL:
				local = attr.Value
			}
		}
		if local != nil {
			address = local
		}
		size := 4
		if m.Data[0] == syscall.AF_INET6 {
			size = 16
		} else if m.Data[0] != syscall.AF_INET {
			continue
		}
		if len(address) < size {
			return nil, fmt.Errorf("short IP address")
		}
		if ip := net.IP(address[:size]).To4(); ip != nil {
			index := int(binary.NativeEndian.Uint32(m.Data[4:8]))
			addresses[index] = append(addresses[index], ip.String())
		}
	}
	return addresses, nil
}
