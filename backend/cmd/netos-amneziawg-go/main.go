// This launcher preserves netOS's protected IPC and systemd readiness contract.
// All packet processing is the pinned, unmodified official AmneziaWG module.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/netos-router/netos/internal/awgruntime"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println("netos-amneziawg-go 3.1.20260828-1")
		return
	}
	if len(os.Args) != 2 || !awgruntime.ValidInterface(os.Args[1]) {
		fmt.Fprintln(os.Stderr, "ожидается интерфейс awg-chN/awg-srvN")
		os.Exit(1)
	}
	if err := awgruntime.Serve(context.Background(), os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
