//go:build !linux

package tun

func init() {
	ensureDevNetTun = func() {}
}
