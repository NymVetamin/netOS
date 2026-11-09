package api

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

func sendWakePacket(name string, packet []byte) error {
	iface, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	protocol := binary.NativeEndian.Uint16([]byte{0x08, 0x42})
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, int(protocol))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	// Query only the selected interface; net.InterfaceByName dumps every link.
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFINDEX, iface); err != nil {
		return err
	}
	index := int(iface.Uint32())
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, iface); err != nil {
		return err
	}
	flags := iface.Uint16()
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFHWADDR, iface); err != nil {
		return err
	}
	if iface.Uint16() != unix.ARPHRD_ETHER || flags&unix.IFF_BROADCAST == 0 || flags&unix.IFF_UP == 0 {
		return fmt.Errorf("интерфейс %s должен быть включённым Ethernet-интерфейсом", name)
	}
	return unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{
		Protocol: protocol, Ifindex: index, Halen: 6,
		Addr: [8]uint8{255, 255, 255, 255, 255, 255},
	})
}
