package eventlog

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// WatchLinks reports cable connect/disconnect of the interfaces watched
// accepts. It subscribes to rtnetlink link notifications: the kernel pushes a
// message per change, so idle cost is one blocked socket read. Kernel
// "Link is Up" lines are not used: virtual NICs and many drivers never print
// them. Returns when ctx ends or the socket cannot be opened.
func WatchLinks(ctx context.Context, log *Log, watched func(name string) bool) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	if unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: unix.RTMGRP_LINK}) != nil {
		return
	}
	// A receive timeout lets the loop notice ctx without a second goroutine.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})
	// Baseline after subscribing: a change between the two is not lost, at
	// worst it is reported against the already new state and skipped.
	running := map[string]bool{}
	if ifaces, err := net.Interfaces(); err == nil {
		for _, i := range ifaces {
			running[i.Name] = i.Flags&net.FlagRunning != 0
		}
	}
	buf := make([]byte, 64<<10)
	for ctx.Err() == nil {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			return
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			continue
		}
		for _, m := range msgs {
			if m.Header.Type != unix.RTM_NEWLINK || len(m.Data) < unix.SizeofIfInfomsg {
				continue
			}
			flags := binary.NativeEndian.Uint32(m.Data[8:12])
			attrs, err := syscall.ParseNetlinkRouteAttr(&m)
			if err != nil {
				continue
			}
			name := ""
			for _, a := range attrs {
				if a.Attr.Type == unix.IFLA_IFNAME {
					name = strings.TrimRight(string(a.Value), "\x00")
				}
			}
			up := flags&unix.IFF_RUNNING != 0
			was, known := running[name]
			running[name] = up
			if name == "" || !known || was == up || !watched(name) {
				continue
			}
			if up {
				log.Add(time.Now(), Internet, Info, name, "кабель подключён"+linkSpeed(name))
			} else {
				log.Add(time.Now(), Internet, Warning, name, "кабель отключён")
			}
		}
	}
}

func linkSpeed(name string) string {
	raw, err := os.ReadFile("/sys/class/net/" + name + "/speed")
	speed := strings.TrimSpace(string(raw))
	if err != nil || speed == "" || strings.HasPrefix(speed, "-") || speed == "0" {
		return ""
	}
	return ", " + speed + " Мбит/с"
}
