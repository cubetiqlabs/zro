//go:build !linux && !darwin

package node

import (
	"context"
	"fmt"

	"golang.org/x/crypto/ssh"
)

func (d *Daemon) serveSession(_ context.Context, ch ssh.Channel, reqs <-chan *ssh.Request, _ string) {
	defer ch.Close()
	for req := range reqs {
		_ = req.Reply(false, nil)
		if req.Type == "shell" || req.Type == "exec" {
			_, _ = fmt.Fprintln(ch.Stderr(), "zro: the built-in SSH server runs on Linux and macOS")
			return
		}
	}
}
