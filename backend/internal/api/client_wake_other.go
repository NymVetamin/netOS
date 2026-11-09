//go:build !linux

package api

import "fmt"

func sendWakePacket(string, []byte) error {
	return fmt.Errorf("Wake-on-LAN поддерживается только в Linux")
}
