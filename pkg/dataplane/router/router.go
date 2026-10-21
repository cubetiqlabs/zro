// Package router describes how traffic to an overlay address is carried.
package router

// RouteTarget describes the path DiscoverAndConnectPeer chose for a peer.
type RouteTarget struct {
	PublicKey   string `json:"public_key"`
	Endpoint    string `json:"endpoint,omitempty"`     // Direct UDP endpoint (e.g. "203.0.113.5:51820")
	ViaPoPCode  string `json:"via_pop_code,omitempty"` // PoP code if relayed (e.g. "KH", "SG")
	IsDirectP2P bool   `json:"is_direct_p2p"`
	Metric      int    `json:"metric"`
}
