package netutil

import (
	"net"
	"os"
	"testing"
)

func TestGetLocalPrivateIP(t *testing.T) {
	ip, err := GetLocalPrivateIP()
	if err != nil {
		t.Fatalf("failed to get private IP: %v", err)
	}
	if ip == nil {
		t.Fatal("expected non-nil IP")
	}
	t.Logf("Detected local private IP: %s", ip.String())
}

func TestResolveEndpointExplicit(t *testing.T) {
	endpoint := ResolveEndpoint("198.51.100.5:51820", 51820, false)
	if endpoint != "198.51.100.5:51820" {
		t.Fatalf("expected 198.51.100.5:51820, got %s", endpoint)
	}

	// Host without port should have defaultPort appended
	endpoint = ResolveEndpoint("198.51.100.5", 51822, false)
	if endpoint != "198.51.100.5:51822" {
		t.Fatalf("expected 198.51.100.5:51822, got %s", endpoint)
	}
}

func TestResolveEndpointPrivateMode(t *testing.T) {
	// 1. Via argument
	endpoint := ResolveEndpoint("private", 51820, false)
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || port != "51820" || host == "" {
		t.Fatalf("expected valid host:51820, got %s", endpoint)
	}

	// 2. Via boolean flag
	endpoint2 := ResolveEndpoint("auto", 51821, true)
	_, port2, err := net.SplitHostPort(endpoint2)
	if err != nil || port2 != "51821" {
		t.Fatalf("expected valid host:51821, got %s", endpoint2)
	}
}

func TestResolveEndpointEnvOverride(t *testing.T) {
	os.Setenv("ZRO_EDGE_PUBLIC_ENDPOINT", "10.200.1.5:51825")
	defer os.Unsetenv("ZRO_EDGE_PUBLIC_ENDPOINT")

	endpoint := ResolveEndpoint("auto", 51820, false)
	if endpoint != "10.200.1.5:51825" {
		t.Fatalf("expected env override 10.200.1.5:51825, got %s", endpoint)
	}

	os.Setenv("ZRO_EDGE_USE_PRIVATE_IP", "true")
	defer os.Unsetenv("ZRO_EDGE_USE_PRIVATE_IP")
	os.Unsetenv("ZRO_EDGE_PUBLIC_ENDPOINT")

	endpointPriv := ResolveEndpoint("auto", 51829, false)
	_, port, err := net.SplitHostPort(endpointPriv)
	if err != nil || port != "51829" {
		t.Fatalf("expected valid port 51829, got %s", endpointPriv)
	}
}

func TestResolveEndpointAuto(t *testing.T) {
	endpoint := ResolveEndpoint("auto", 51820, false)
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || port != "51820" || host == "" {
		t.Fatalf("expected resolved host:51820, got %s", endpoint)
	}
	t.Logf("Auto-resolved endpoint: %s", endpoint)
}
