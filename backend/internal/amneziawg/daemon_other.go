//go:build !linux

package amneziawg

import (
	"context"
	"fmt"
)

func serve(context.Context, string) error {
	return fmt.Errorf("AmneziaWG работает только в Linux")
}
