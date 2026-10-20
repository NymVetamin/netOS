//go:build linux

package services

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func subscribeKeaLinks(ctx context.Context) (<-chan error, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "kea-netlink")
	raw, err := file.SyscallConn()
	if err != nil {
		file.Close()
		return nil, err
	}
	events := make(chan error, 64)
	go func() {
		defer close(events)
		defer file.Close()
		stop := context.AfterFunc(ctx, func() { file.Close() })
		defer stop()
		buf := make([]byte, 64*1024)
		for {
			var n, flags int
			var from unix.Sockaddr
			var recvErr error
			err := raw.Read(func(fd uintptr) bool {
				for {
					n, _, flags, from, recvErr = unix.Recvmsg(int(fd), buf, nil, 0)
					if recvErr != unix.EINTR {
						break
					}
				}
				return recvErr != unix.EAGAIN && recvErr != unix.EWOULDBLOCK
			})
			if err == nil {
				err = recvErr
			}
			if err == nil && flags&unix.MSG_TRUNC != 0 {
				err = fmt.Errorf("обрезано сообщение netlink")
			}
			if err == nil {
				// Only the kernel may trigger link notifications.
				if sender, ok := from.(*unix.SockaddrNetlink); !ok || sender.Pid != 0 {
					continue
				}
				var messages []syscall.NetlinkMessage
				messages, err = syscall.ParseNetlinkMessage(buf[:n])
				relevant := false
				for _, message := range messages {
					switch message.Header.Type {
					case unix.RTM_NEWLINK, unix.RTM_DELLINK, unix.RTM_NEWADDR, unix.RTM_DELADDR:
						relevant = true
					case unix.NLMSG_OVERRUN, unix.NLMSG_ERROR:
						err = fmt.Errorf("потеря событий netlink (тип %d)", message.Header.Type)
					}
				}
				if err == nil && !relevant {
					continue
				}
			}
			if ctx.Err() != nil {
				return
			}
			select {
			case events <- err:
			default:
				// Closing an overflowing queue forces re-subscription and a
				// full snapshot; never silently continue after dropped events.
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return events, nil
}
