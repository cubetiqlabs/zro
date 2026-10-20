package netutil

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// PublicIPServices contains fast and reliable public IP reflection endpoints.
var PublicIPServices = []string{
	"https://api.ipify.org",
	"https://icanhazip.com",
	"https://ifconfig.me/ip",
	"https://checkip.amazonaws.com",
}

// GetOutboundIP determines the preferred local outbound IP using kernel routing.
func GetOutboundIP() (net.IP, error) {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || localAddr == nil {
		return nil, fmt.Errorf("failed to cast local UDP address")
	}
	return localAddr.IP, nil
}

// GetLocalPrivateIP returns the local machine's non-loopback private IPv4 address.
func GetLocalPrivateIP() (net.IP, error) {
	// 1. Try outbound route IP
	if ip, err := GetOutboundIP(); err == nil && ip != nil && !ip.IsLoopback() {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
	}

	// 2. Iterate network interfaces
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil || ip.IsLoopback() {
					continue
				}
				if ip4 := ip.To4(); ip4 != nil {
					return ip4, nil
				}
			}
		}
	}

	// 3. Fallback to loopback
	return net.ParseIP("127.0.0.1"), nil
}

// DiscoverPublicIP queries public IP services with a timeout.
func DiscoverPublicIP(ctx context.Context, timeout time.Duration) (net.IP, error) {
	client := &http.Client{Timeout: timeout}

	for _, svc := range PublicIPServices {
		req, err := http.NewRequestWithContext(ctx, "GET", svc, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}

		trimmed := strings.TrimSpace(string(body))
		ip := net.ParseIP(trimmed)
		if ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsPrivate() {
			return ip.To4(), nil
		}
	}

	return nil, fmt.Errorf("public IP discovery failed across all providers")
}

// ResolveEndpoint resolves the endpoint (host:port) based on configuration, environment, and auto-detection:
// - Explicit endpoint (e.g. "173.1.1.1:51820" or via ZRO_EDGE_PUBLIC_ENDPOINT env)
// - Private/Internal mode ("private", "internal", "lan", "local" or usePrivateIP=true)
// - Auto mode ("auto", "detect", or empty): discovers public IP with graceful fallback to private IP.
func ResolveEndpoint(configured string, defaultPort int, usePrivateIP bool) string {
	// 1. Check environment variable overrides
	envEndpoint := os.Getenv("ZRO_EDGE_PUBLIC_ENDPOINT")
	if envEndpoint == "" {
		envEndpoint = os.Getenv("PUBLIC_ENDPOINT")
	}
	if envEndpoint != "" {
		configured = envEndpoint
	}

	if os.Getenv("ZRO_EDGE_USE_PRIVATE_IP") == "true" || os.Getenv("USE_PRIVATE_IP") == "true" {
		usePrivateIP = true
	}

	configured = strings.TrimSpace(configured)

	// Check if only an IP was provided via env
	if envIP := os.Getenv("ZRO_EDGE_PUBLIC_IP"); envIP != "" {
		return net.JoinHostPort(envIP, strconv.Itoa(defaultPort))
	}
	if envIP := os.Getenv("PUBLIC_IP"); envIP != "" {
		return net.JoinHostPort(envIP, strconv.Itoa(defaultPort))
	}

	// 2. Private/Internal IP mode
	lowered := strings.ToLower(configured)
	if usePrivateIP || lowered == "private" || lowered == "internal" || lowered == "lan" || lowered == "local" {
		ip, _ := GetLocalPrivateIP()
		return net.JoinHostPort(ip.String(), strconv.Itoa(defaultPort))
	}

	// 3. Explicit Host:Port provided
	if configured != "" && lowered != "auto" && lowered != "detect" && lowered != "0.0.0.0" {
		if strings.Contains(configured, ":") {
			return configured
		}
		return net.JoinHostPort(configured, strconv.Itoa(defaultPort))
	}

	// 4. Auto mode: Attempt Public IP discovery first
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pubIP, err := DiscoverPublicIP(ctx, 2*time.Second)
	if err == nil && pubIP != nil {
		return net.JoinHostPort(pubIP.String(), strconv.Itoa(defaultPort))
	}

	// 5. Fallback to Local/Private IP if public discovery fails or in standalone/offline host
	privIP, _ := GetLocalPrivateIP()
	return net.JoinHostPort(privIP.String(), strconv.Itoa(defaultPort))
}
