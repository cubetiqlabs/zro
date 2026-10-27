package node

import (
	"errors"
	"os"
)

// ponytail: no PTY on macOS yet; commands run without one (zro ssh host cmd).
func openPTY() (ptmx, tty *os.File, err error) {
	return nil, nil, errors.New("interactive shells need Linux; run a command instead: zro ssh host -- cmd")
}

func setWinsize(*os.File, uint32, uint32) {}
