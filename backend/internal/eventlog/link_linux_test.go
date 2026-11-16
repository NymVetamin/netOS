package eventlog

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// linkMsg builds one rtnetlink link message as the kernel sends it.
func linkMsg(typ uint16, family uint8, index int32, flags uint32, name string) []byte {
	attr := make([]byte, 4+(len(name)+1+3)&^3)
	binary.NativeEndian.PutUint16(attr[0:], uint16(4+len(name)+1))
	binary.NativeEndian.PutUint16(attr[2:], unix.IFLA_IFNAME)
	copy(attr[4:], name)
	msg := make([]byte, unix.SizeofNlMsghdr+unix.SizeofIfInfomsg, unix.SizeofNlMsghdr+unix.SizeofIfInfomsg+len(attr))
	binary.NativeEndian.PutUint16(msg[4:], typ)
	msg[unix.SizeofNlMsghdr] = family
	binary.NativeEndian.PutUint32(msg[unix.SizeofNlMsghdr+4:], uint32(index))
	binary.NativeEndian.PutUint32(msg[unix.SizeofNlMsghdr+8:], flags)
	msg = append(msg, attr...)
	binary.NativeEndian.PutUint32(msg[0:], uint32(len(msg)))
	return msg
}

func TestLinkStateFollowsIndexAndIsRemovedWithLink(t *testing.T) {
	l := New()
	w := &linkWatch{log: l, watched: func(name string) bool { return name != "veth-x" }, running: map[int32]bool{}}
	const up = unix.IFF_UP | unix.IFF_RUNNING
	w.handle(linkMsg(unix.RTM_NEWLINK, unix.AF_UNSPEC, 5, up, "eth9")) // first sight: nothing to compare
	w.handle(linkMsg(unix.RTM_NEWLINK, unix.AF_UNSPEC, 5, unix.IFF_UP, "eth9"))
	w.handle(linkMsg(unix.RTM_NEWLINK, unix.AF_UNSPEC, 5, unix.IFF_UP, "eth9")) // repeated state
	w.handle(linkMsg(unix.RTM_NEWLINK, unix.AF_UNSPEC, 5, up, "wan0"))          // renamed while down
	w.handle(linkMsg(unix.RTM_DELLINK, unix.AF_BRIDGE, 5, up, "wan0"))          // left a bridge, still exists
	w.handle(linkMsg(unix.RTM_NEWLINK, unix.AF_UNSPEC, 5, unix.IFF_UP, "wan0"))
	w.handle(linkMsg(unix.RTM_NEWLINK, unix.AF_UNSPEC, 6, up, "veth-x"))
	w.handle(linkMsg(unix.RTM_NEWLINK, unix.AF_UNSPEC, 6, 0, "veth-x")) // not watched
	want := "warning eth9: кабель отключён\ninfo wan0: кабель подключён\nwarning wan0: кабель отключён"
	if got := strings.Join(messages(l, Internet), "\n"); got != want {
		t.Fatalf("got:\n%s", got)
	}
	w.handle(linkMsg(unix.RTM_DELLINK, unix.AF_UNSPEC, 5, 0, "wan0"))
	w.handle(linkMsg(unix.RTM_DELLINK, unix.AF_UNSPEC, 6, 0, "veth-x"))
	// Container-style churn: every link gets a new index and name.
	for i := int32(100); i < 1100; i++ {
		name := fmt.Sprintf("veth%d", i)
		w.handle(linkMsg(unix.RTM_NEWLINK, unix.AF_UNSPEC, i, up, name))
		w.handle(linkMsg(unix.RTM_DELLINK, unix.AF_UNSPEC, i, 0, name))
	}
	if len(w.running) != 0 {
		t.Fatalf("state of deleted links kept: %d", len(w.running))
	}
}

// A consumer that falls behind makes the kernel drop notifications (ENOBUFS).
// The watcher must keep working and end up reporting the real state.
func TestIntegrationLinkWatchOverflow(t *testing.T) {
	if os.Getenv("NETOS_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("isolated root integration only")
	}
	self, _ := os.Readlink("/proc/self/ns/net")
	host, _ := os.Readlink("/proc/1/ns/net")
	if self == host {
		t.Fatal("refusing host namespace")
	}
	ip := func(stdin string, args ...string) {
		t.Helper()
		cmd := exec.Command("ip", args...)
		cmd.Stdin = strings.NewReader(stdin)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	socket := func() int {
		t.Helper()
		fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { unix.Close(fd) })
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1) // the kernel's minimum
		if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: unix.RTMGRP_LINK}); err != nil {
			t.Fatal(err)
		}
		return fd
	}
	ip("", "link", "add", "nwatch0", "type", "dummy")
	ip("", "link", "set", "nwatch0", "up")

	l := New()
	gate, entered := make(chan struct{}), make(chan struct{}, 1)
	w := &linkWatch{log: l, watched: func(name string) bool {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-gate // the slow consumer
		return name == "nwatch0"
	}}
	control, fd := socket(), socket()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.run(ctx, fd) }()
	time.Sleep(300 * time.Millisecond) // baseline taken

	ip("", "link", "set", "nwatch0", "down")
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the watcher did not see the link go down")
	}
	var batch strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&batch, "link add nchurn%d type dummy\nlink del nchurn%d\n", i, i)
	}
	batch.WriteString("link set nwatch0 up\n")
	ip(batch.String(), "-batch", "-")
	// The identical, unread control socket proves the churn overflowed.
	buf := make([]byte, 64<<10)
	overflowed := false
	for {
		_, _, err := unix.Recvfrom(control, buf, unix.MSG_DONTWAIT)
		if err == unix.ENOBUFS {
			overflowed = true
		} else if err != nil {
			break
		}
	}
	if !overflowed {
		t.Fatal("the churn did not overflow a minimal netlink buffer; the test proves nothing")
	}
	close(gate)
	wait := func(want string) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
			got := strings.Join(messages(l, Internet), "\n")
			if got == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("got:\n%s\nwant:\n%s", got, want)
			}
		}
	}
	// The final "up" was dropped by the kernel; only the resync can show it.
	wait("warning nwatch0: кабель отключён\ninfo nwatch0: кабель подключён")
	ip("", "link", "set", "nwatch0", "down") // and the watcher is still alive
	wait("warning nwatch0: кабель отключён\ninfo nwatch0: кабель подключён\nwarning nwatch0: кабель отключён")
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// lo and nwatch0: the 200 deleted links left nothing behind.
	if len(w.running) != 2 {
		t.Fatalf("state entries: %d", len(w.running))
	}
}
