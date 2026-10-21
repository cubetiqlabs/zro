// Package relay defines the transport WireGuard datagrams use when UDP cannot
// reach a peer (for example a network that blocks UDP): an authenticated
// store-and-forward channel keyed by WireGuard public keys, such as DERP.
package relay

// KeyLen is the length of a WireGuard public key.
const KeyLen = 32

// Packet is a datagram received through a relay, tagged with the sender's
// public key as authenticated by the relay.
type Packet struct {
	SrcPubKey [KeyLen]byte
	Payload   []byte
}

// Transport sends datagrams to, and receives them from, peers by public key.
// Recv is closed when the transport is no longer usable.
type Transport interface {
	Send(dst [KeyLen]byte, packet []byte) error
	Recv() <-chan Packet
}
