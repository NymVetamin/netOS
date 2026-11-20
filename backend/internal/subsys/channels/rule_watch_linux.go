package channels

import "golang.org/x/sys/unix"

type ruleWatch int

func watchIPv4Rules() (ruleWatch, bool) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, false
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: unix.RTMGRP_IPV4_RULE}); err != nil {
		unix.Close(fd)
		return -1, false
	}
	return ruleWatch(fd), true
}

func (w ruleWatch) unchanged() bool {
	// Data, an overflow, or a socket error all retire the snapshot. Leave the
	// queue unread so no notification can be lost between checking and use.
	n, err := unix.Poll([]unix.PollFd{{Fd: int32(w), Events: unix.POLLIN}}, 0)
	return err == nil && n == 0
}

func (w ruleWatch) close() { unix.Close(int(w)) }
