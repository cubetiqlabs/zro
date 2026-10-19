package puncher

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"
)

var (
	MagicPing = []byte("ZRO_P2P_PING_V1")
	MagicPong = []byte("ZRO_P2P_PONG_V1")
)

// PunchResult describes the result of a P2P hole punch attempt.
type PunchResult struct {
	Success        bool          `json:"success"`
	RemoteEndpoint string        `json:"remote_endpoint"`
	RTT            time.Duration `json:"rtt"`
}

// Punch attempts bidirectional NAT hole punching to remoteEndpoint over localConn.
func Punch(ctx context.Context, localConn *net.UDPConn, remoteEndpoint string, timeout time.Duration) (*PunchResult, error) {
	remoteAddr, err := net.ResolveUDPAddr("udp", remoteEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve remote endpoint: %w", err)
	}

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	buf := make([]byte, 512)
	start := time.Now()

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return &PunchResult{Success: false, RemoteEndpoint: remoteEndpoint}, ctx.Err()
		case <-ticker.C:
			// Send PING burst
			_, _ = localConn.WriteToUDP(MagicPing, remoteAddr)

			// Non-blocking or short-read check
			_ = localConn.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
			n, from, err := localConn.ReadFromUDP(buf)
			if err == nil && from.IP.Equal(remoteAddr.IP) {
				payload := buf[:n]
				if bytes.Equal(payload, MagicPing) {
					// Respond with PONG
					_, _ = localConn.WriteToUDP(MagicPong, from)
				} else if bytes.Equal(payload, MagicPong) {
					// Hole punch confirmed!
					rtt := time.Since(start)
					slog.Info("P2P hole punch established", "remote", remoteEndpoint, "rtt", rtt)
					return &PunchResult{
						Success:        true,
						RemoteEndpoint: remoteEndpoint,
						RTT:            rtt,
					}, nil
				}
			}
		}
	}

	return &PunchResult{
		Success:        false,
		RemoteEndpoint: remoteEndpoint,
	}, nil
}
