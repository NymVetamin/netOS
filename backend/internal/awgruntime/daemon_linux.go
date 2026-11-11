//go:build linux

package awgruntime

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

func Serve(ctx context.Context, name string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("AmneziaWG требует root")
	}
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGTERM, os.Interrupt)
	defer cancel()
	if err := os.MkdirAll(SocketDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(SocketDir, name+".sock")
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		c.Close()
		return fmt.Errorf("AmneziaWG уже запущен")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("вместо сокета AmneziaWG существует чужой файл")
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	if _, err := net.InterfaceByName(name); err == nil {
		return fmt.Errorf("интерфейс AmneziaWG уже существует")
	}
	tdev, err := tun.CreateTUN(name, 1420)
	if err != nil {
		return fmt.Errorf("создание AmneziaWG TUN: %w", err)
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	// Up enables the UDP bind even before address assignment. The caller then
	// applies keys/peers and addresses through the normal apply transaction.
	if err := dev.Up(); err != nil {
		return err
	}
	go func() {
		select {
		case <-dev.Wait():
			listener.Close()
		case <-ctx.Done():
		}
	}()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	// Type=notify lets systemd run ExecStartPost only once IPC is ready.
	// Those commands restore configuration/addressing on automatic restarts.
	if socket := os.Getenv("NOTIFY_SOCKET"); socket != "" {
		c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
		if err != nil {
			return fmt.Errorf("уведомление systemd: %w", err)
		}
		_ = c.SetWriteDeadline(time.Now().Add(time.Second))
		_, err = c.Write([]byte("READY=1"))
		c.Close()
		if err != nil {
			return fmt.Errorf("уведомление systemd: %w", err)
		}
	}
	for {
		client, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		// Local management is sequential and bounded; a stuck root client must
		// not leave unbounded goroutines or prevent shutdown indefinitely.
		_ = client.SetDeadline(time.Now().Add(5 * time.Second))
		dev.IpcHandle(client)
	}
}
