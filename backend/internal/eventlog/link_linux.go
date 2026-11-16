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
// them. Returns when ctx ends; a watcher that cannot work says so in the log
// instead of leaving the topic silently empty.
func WatchLinks(ctx context.Context, log *Log, watched func(name string) bool) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err == nil {
		defer unix.Close(fd)
		if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: unix.RTMGRP_LINK}); err == nil {
			err = (&linkWatch{log: log, watched: watched}).run(ctx, fd)
		}
	}
	if err != nil && ctx.Err() == nil {
		log.Add(time.Now(), Internet, Warning, "порты", "слежение за кабелем остановлено до перезапуска netOS: "+err.Error())
	}
}

// linkWatch remembers the carrier state per interface index: one entry per
// existing link, removed with the link, so renames and veth churn do not grow it.
type linkWatch struct {
	log     *Log
	watched func(name string) bool
	running map[int32]bool
}

func (w *linkWatch) run(ctx context.Context, fd int) error {
	// A receive timeout lets the loop notice ctx without a second goroutine.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})
	// Baseline after subscribing: a change between the two is not lost, at
	// worst it is reported against the already new state and skipped.
	w.resync(false)
	buf := make([]byte, 64<<10)
	for ctx.Err() == nil {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		switch err {
		case nil:
			w.handle(buf[:n])
		case unix.EAGAIN, unix.EINTR:
		case unix.ENOBUFS:
			// The kernel dropped notifications. What is still queued is older
			// than the loss and would be reported as the final state, so it
			// is discarded and the present state is read anew.
			for {
				if _, _, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT); err != nil && err != unix.ENOBUFS && err != unix.EINTR {
					break
				}
			}
			w.resync(true)
		default:
			return err
		}
	}
	return nil
}

// resync replaces the remembered state with the kernel's; with report set,
// differences from what was remembered become events. One link dump.
func (w *linkWatch) resync(report bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	old := w.running
	w.running = make(map[int32]bool, len(ifaces))
	for _, i := range ifaces {
		if was, known := old[int32(i.Index)]; known {
			w.running[int32(i.Index)] = was
		}
		if report {
			w.set(int32(i.Index), i.Name, i.Flags&net.FlagRunning != 0)
		} else {
			w.running[int32(i.Index)] = i.Flags&net.FlagRunning != 0
		}
	}
}

func (w *linkWatch) handle(buf []byte) {
	msgs, err := syscall.ParseNetlinkMessage(buf)
	if err != nil {
		return
	}
	for _, m := range msgs {
		if len(m.Data) < unix.SizeofIfInfomsg {
			continue
		}
		index := int32(binary.NativeEndian.Uint32(m.Data[4:8]))
		switch m.Header.Type {
		case unix.RTM_DELLINK:
			// AF_BRIDGE reports a port leaving its bridge the same way; the
			// link itself is gone only for AF_UNSPEC.
			if m.Data[0] == unix.AF_UNSPEC {
				delete(w.running, index)
			}
		case unix.RTM_NEWLINK:
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
			w.set(index, name, binary.NativeEndian.Uint32(m.Data[8:12])&unix.IFF_RUNNING != 0)
		}
	}
}

// set records the state of one link and reports a change of a watched one.
// A link seen for the first time has no previous state to compare with.
func (w *linkWatch) set(index int32, name string, up bool) {
	was, known := w.running[index]
	w.running[index] = up
	if name == "" || !known || was == up || !w.watched(name) {
		return
	}
	if up {
		w.log.Add(time.Now(), Internet, Info, name, "кабель подключён"+linkSpeed(name))
	} else {
		w.log.Add(time.Now(), Internet, Warning, name, "кабель отключён")
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
