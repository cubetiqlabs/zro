// Package netcfg programs host network state needed by the overlay data plane.
//
// ZRO runs on Linux (containers and VPS hosts). Commands are executed through
// the standard `ip` utility so the binary does not need to link netlink. On
// non-Linux hosts these functions validate their inputs and then no-op, which
// keeps unit tests and local development on macOS/Windows working.
package netcfg

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// Linux interface names are limited to 15 characters (IFNAMSIZ - 1).
var ifaceRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

// ValidateInterfaceName checks that name is safe to pass to `ip`.
func ValidateInterfaceName(name string) error {
	if !ifaceRe.MatchString(name) {
		return fmt.Errorf("invalid interface name %q", name)
	}
	return nil
}

func validateIP(value string) (net.IP, error) {
	ip := net.ParseIP(value)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address %q", value)
	}
	return ip, nil
}

// EnsureLinkUp sets the MTU and brings the interface up.
func EnsureLinkUp(name string, mtu int) error {
	if err := ValidateInterfaceName(name); err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return nil
	}
	args := []string{"link", "set", "dev", name}
	if mtu > 0 {
		args = append(args, "mtu", strconv.Itoa(mtu))
	}
	args = append(args, "up")
	return run("ip", args...)
}

// ConfigureOverlay assigns the node's overlay addresses and brings the link up.
// Using `addr replace` keeps the operation idempotent across restarts.
func ConfigureOverlay(name, ipv4, ipv6 string, mtu int) error {
	if err := ValidateInterfaceName(name); err != nil {
		return err
	}
	var want4, want6 net.IP
	var err error
	if ipv4 != "" {
		if want4, err = validateIP(ipv4); err != nil {
			return err
		}
	}
	if ipv6 != "" {
		if want6, err = validateIP(ipv6); err != nil {
			return err
		}
	}
	if runtime.GOOS != "linux" {
		return nil
	}

	if err := EnsureLinkUp(name, mtu); err != nil {
		return err
	}
	if want4 != nil {
		if err := run("ip", "addr", "replace", want4.String()+"/32", "dev", name); err != nil {
			return err
		}
	}
	if want6 != nil {
		if err := run("ip", "-6", "addr", "replace", want6.String()+"/128", "dev", name); err != nil {
			return err
		}
	}
	return nil
}

// AddHostRoute points a single overlay /32 (or /128) at the interface so the
// host stack sends that peer's traffic into the WireGuard device.
func AddHostRoute(name, ipValue string) error {
	if err := ValidateInterfaceName(name); err != nil {
		return err
	}
	ip, err := validateIP(ipValue)
	if err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return nil
	}
	if ip.To4() != nil {
		return run("ip", "route", "replace", ip.String()+"/32", "dev", name)
	}
	return run("ip", "-6", "route", "replace", ip.String()+"/128", "dev", name)
}

// AddSubnetRoute points a CIDR at the interface (used by gateway/edge relay).
func AddSubnetRoute(name, cidr string) error {
	if err := ValidateInterfaceName(name); err != nil {
		return err
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	if runtime.GOOS != "linux" {
		return nil
	}
	if network.IP.To4() != nil {
		return run("ip", "route", "replace", network.String(), "dev", name)
	}
	return run("ip", "-6", "route", "replace", network.String(), "dev", name)
}

func run(bin string, args ...string) error {
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// EnableForwarding turns on IPv4 and IPv6 forwarding so an Edge PoP can relay
// packets between overlay peers. Failures are returned for logging; callers may
// continue when the host already has forwarding enabled.
func EnableForwarding() error {
	if runtime.GOOS != "linux" {
		return nil
	}
	var failures []string
	for _, path := range []string{
		"/proc/sys/net/ipv4/ip_forward",
		"/proc/sys/net/ipv6/conf/all/forwarding",
	} {
		if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", path, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("could not enable forwarding: %s", strings.Join(failures, "; "))
	}
	return nil
}
