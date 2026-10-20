//go:build linux

package tun

import (
	"os"

	"golang.org/x/sys/unix"
)

func init() {
	ensureDevNetTun = func() {
		if _, err := os.Stat("/dev/net/tun"); os.IsNotExist(err) {
			_ = os.MkdirAll("/dev/net", 0755)
			_ = unix.Mknod("/dev/net/tun", unix.S_IFCHR|0666, int(unix.Mkdev(10, 200)))
		}
	}
}
