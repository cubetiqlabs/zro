package puncher

import (
	"bytes"
)

var (
	MagicPing = []byte("ZRO_P2P_PING_V1")
	MagicPong = []byte("ZRO_P2P_PONG_V1")
)

// IsPing reports whether packet is a hole-punch ping.
func IsPing(packet []byte) bool { return bytes.Equal(packet, MagicPing) }

// IsPong reports whether packet is a hole-punch pong.
func IsPong(packet []byte) bool { return bytes.Equal(packet, MagicPong) }
