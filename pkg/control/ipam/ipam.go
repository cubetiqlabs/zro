package ipam

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
)

var (
	ErrSubnetFull  = errors.New("subnet has no available IP addresses")
	ErrInvalidCIDR = errors.New("invalid CIDR specification")
)

// PoPReserve is how many addresses at the top of a large subnet are kept for
// edge PoPs (index 1 is the last usable address). Subnets of 1024 addresses or
// fewer reserve nothing, so small networks keep their whole range.
const PoPReserve = 250

// IPAM manages overlay IP allocation for virtual networks.
type IPAM struct {
	mu            sync.Mutex
	subnet        *net.IPNet
	baseIP        uint32
	netmask       uint32
	broadcastIP   uint32
	limit         uint32 // first address AllocateNext may not hand out
	allocatedIPv4 map[uint32]bool
}

// NewIPAM creates an IPAM instance for a given IPv4 CIDR string (e.g. "100.64.0.0/16").
func NewIPAM(cidr string, existingAllocations []string) (*IPAM, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidCIDR, cidr)
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("only IPv4 CIDRs currently supported for IPAM allocator")
	}

	mask := binary.BigEndian.Uint32(ipNet.Mask)
	base := binary.BigEndian.Uint32(ipv4) & mask
	broadcast := base | ^mask

	allocator := &IPAM{
		subnet:        ipNet,
		baseIP:        base,
		netmask:       mask,
		broadcastIP:   broadcast,
		allocatedIPv4: make(map[uint32]bool),
	}

	allocator.limit = broadcast
	if broadcast-base > 4*PoPReserve {
		allocator.limit = broadcast - PoPReserve
	}

	// Reserve network address (.0) and broadcast address
	allocator.allocatedIPv4[base] = true
	allocator.allocatedIPv4[broadcast] = true

	// Reserve .1 for virtual gateway/DNS
	allocator.allocatedIPv4[base+1] = true

	// Pre-populate existing allocations from database
	for _, ipStr := range existingAllocations {
		parsed := net.ParseIP(ipStr).To4()
		if parsed != nil {
			allocator.allocatedIPv4[binary.BigEndian.Uint32(parsed)] = true
		}
	}

	return allocator, nil
}

// AllocateNext finds and reserves the next available IPv4 address in the subnet.
func (i *IPAM) AllocateNext() (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	// Start searching from base + 2 (.2 onwards)
	current := i.baseIP + 2
	for current < i.limit {
		if !i.allocatedIPv4[current] {
			i.allocatedIPv4[current] = true
			return uint32ToIP(current).String(), nil
		}
		current++
	}

	return "", ErrSubnetFull
}

// Release frees an allocated IP address back to the pool.
func (i *IPAM) Release(ipStr string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	ip := net.ParseIP(ipStr).To4()
	if ip != nil {
		delete(i.allocatedIPv4, binary.BigEndian.Uint32(ip))
	}
}

// DeriveIPv6 computes a deterministic IPv6 address from a prefix and the node's assigned IPv4.
// e.g. prefix "fd00:zro::/64" + "100.64.0.10" -> "fd00:zro::100:64:0:10" or similar standard RFC mapping.
func DeriveIPv6(prefix string, ipv4Str string) (string, error) {
	_, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrInvalidCIDR, prefix)
	}

	v4 := net.ParseIP(ipv4Str).To4()
	if v4 == nil {
		return "", errors.New("invalid IPv4 address for derivation")
	}

	v6 := make(net.IP, 16)
	copy(v6[:8], ipNet.IP[:8])
	// Place IPv4 bytes in the low 32 bits
	copy(v6[12:], v4)

	return v6.String(), nil
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

// PoPAddress is the overlay address of the edge PoP with the given index
// (1..PoPReserve), counted down from the top of cidr.
func PoPAddress(cidr string, index int) (string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() == nil {
		return "", fmt.Errorf("%w: %s", ErrInvalidCIDR, cidr)
	}
	if index < 1 || index > PoPReserve {
		return "", fmt.Errorf("pop index %d out of range 1..%d", index, PoPReserve)
	}
	mask := binary.BigEndian.Uint32(ipNet.Mask)
	top := binary.BigEndian.Uint32(ipNet.IP.To4()) | ^mask
	return uint32ToIP(top - uint32(index)).String(), nil
}
