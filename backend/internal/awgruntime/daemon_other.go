//go:build !linux

package awgruntime

import (
	"context"
	"fmt"
)

func Serve(context.Context, string) error {
	return fmt.Errorf("AmneziaWG работает только в Linux")
}
