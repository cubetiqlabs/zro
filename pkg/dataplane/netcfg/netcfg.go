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
	return enableForwarding(forwardingPaths)
}

// EnsureForwardAccept lets the host firewall pass relayed overlay traffic that
// enters and leaves through the same interface. Docker sets the FORWARD policy
// to DROP, which silently kills edge relaying. It is a no-op when no firewall
// tool exists or the chain is not restrictive.
func EnsureForwardAccept(name string) error {
	if err := ValidateInterfaceName(name); err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return nil
	}
	var errs []string
	for _, bin := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(bin); err != nil {
			continue
		}
		rule := []string{"FORWARD", "-i", name, "-o", name, "-j", "ACCEPT"}
		if exec.Command(bin, append([]string{"-C"}, rule...)...).Run() == nil {
			continue // already present
		}
		if err := run(bin, append([]string{"-I"}, rule...)...); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("could not allow overlay forwarding: %s", strings.Join(errs, "; "))
	}
	return nil
}

var forwardingPaths = []string{
	"/proc/sys/net/ipv4/ip_forward",
	"/proc/sys/net/ipv6/conf/all/forwarding",
}

// enableForwarding sets each sysctl file to 1. A file already at 1 is left
// alone, which is the case in containers started with `sysctls:` where /proc/sys
// is read-only.
func enableForwarding(paths []string) error {
	var failures []string
	for _, path := range paths {
		if cur, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(cur)) == "1" {
			continue
		}
		if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", path, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("could not enable forwarding (in Docker set sysctls net.ipv4.ip_forward=1 and net.ipv6.conf.all.forwarding=1): %s", strings.Join(failures, "; "))
	}
	return nil
}

// ConfigureDNS sends lookups for domain (and only that domain) to nameserver
// through the interface, using systemd-resolved. Other systems return an
// error so the caller can tell the operator what to set.
func ConfigureDNS(name, nameserver, domain string) error {
	if err := ValidateInterfaceName(name); err != nil {
		return err
	}
	if _, err := validateIP(nameserver); err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("split DNS is only configured automatically with systemd-resolved")
	}
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return fmt.Errorf("resolvectl not found (systemd-resolved)")
	}
	if err := run("resolvectl", "dns", name, nameserver); err != nil {
		return err
	}
	return run("resolvectl", "domain", name, "~"+strings.TrimPrefix(domain, "~"))
}
