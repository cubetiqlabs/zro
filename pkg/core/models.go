package core

import (
	"crypto/rand"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// GenerateNetworkID generates a 16-hex character ZeroTier-styled network ID (e.g. "8056c2e21c000001").
func GenerateNetworkID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// StringList is a JSON-serialized slice of strings for tags, metadata, etc.
type StringList []string

// Value implements driver.Valuer for database storage.
func (s StringList) Value() (driver.Value, error) {
	if s == nil {
		return "[]", nil
	}
	return json.Marshal(s)
}

// Scan implements sql.Scanner for database retrieval.
func (s *StringList) Scan(value any) error {
	if value == nil {
		*s = []string{}
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		str, ok := value.(string)
		if !ok {
			return errors.New("cannot scan type into StringList")
		}
		bytes = []byte(str)
	}
	return json.Unmarshal(bytes, s)
}

// Tenant represents an organization or account in ZRO.
type Tenant struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	Name      string    `gorm:"size:255;not null" json:"name"`
	Slug      string    `gorm:"size:100;uniqueIndex;not null" json:"slug"`
	APIKey    string    `gorm:"size:128;uniqueIndex;not null" json:"api_key"`
	IsActive  bool      `gorm:"default:true" json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Networks []Network `gorm:"foreignKey:TenantID" json:"networks,omitempty"`
}

// Network represents a virtual private overlay network (VPC/Ether-switch space).
// ID uses ZeroTier-style 16-hex characters (e.g. "8056c2e21c000001").
type Network struct {
	ID        string    `gorm:"size:16;primaryKey" json:"id"`
	TenantID  uuid.UUID `gorm:"type:uuid;not null;index" json:"tenant_id"`
	Name      string    `gorm:"size:255;not null" json:"name"`
	Slug      string    `gorm:"size:100;not null" json:"slug"`
	IPv4CIDR  string    `gorm:"size:50;not null;default:'100.64.0.0/10'" json:"ipv4_cidr"`
	IPv6CIDR  string    `gorm:"size:50;not null;default:'fd00:cafe::/64'" json:"ipv6_cidr"`
	DNSDomain string    `gorm:"size:255;default:'zro.internal'" json:"dns_domain"`
	MTU       int       `gorm:"default:1420" json:"mtu"`
	IsActive  bool      `gorm:"default:true" json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Nodes    []Node    `gorm:"foreignKey:NetworkID" json:"nodes,omitempty"`
	ACLRules []ACLRule `gorm:"foreignKey:NetworkID" json:"acl_rules,omitempty"`
	Routes   []Route   `gorm:"foreignKey:NetworkID" json:"routes,omitempty"`
}

// EdgePoP represents a globally distributed Edge Data Plane Node (Public IP PoP).
type EdgePoP struct {
	ID             uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	PoPCode        string    `gorm:"size:10;uniqueIndex;not null" json:"pop_code"` // e.g. "KH", "SG", "US", "HK", "DE"
	Region         string    `gorm:"size:100;not null" json:"region"`
	PublicEndpoint string    `gorm:"size:100;not null" json:"public_endpoint"` // e.g. "173.1.1.1:51820"
	PublicKey      string    `gorm:"size:64;not null" json:"public_key"`
	PrivateKey     string    `gorm:"size:64" json:"-"` // encrypted / kept local to PoP
	IsAnycast      bool      `gorm:"default:false" json:"is_anycast"`
	Weight         int       `gorm:"default:100" json:"weight"`
	IsHealthy      bool      `gorm:"default:true" json:"is_healthy"`
	LastSeenAt     time.Time `json:"last_seen_at"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// NodeType defines the operational role of a node.
type NodeType string

const (
	NodeTypePeer    NodeType = "peer"
	NodeTypeGateway NodeType = "gateway"
	NodeTypeTunnel  NodeType = "tunnel"
)

// Node represents an IPless client, agent, internal service, or gateway in the mesh.
type Node struct {
	ID             uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	NetworkID      string     `gorm:"size:16;not null;index" json:"network_id"`
	Hostname       string     `gorm:"size:255;not null" json:"hostname"`
	PublicKey      string     `gorm:"size:64;not null;index" json:"public_key"`
	OverlayIPv4    string     `gorm:"size:50;not null;index" json:"overlay_ipv4"`
	OverlayIPv6    string     `gorm:"size:50;not null" json:"overlay_ipv6"`
	AssignedPoPID  *uuid.UUID `gorm:"type:uuid;index" json:"assigned_pop_id,omitempty"`
	NodeType       NodeType   `gorm:"size:30;default:'peer'" json:"node_type"`
	Tags           StringList `gorm:"type:text" json:"tags"`
	AllowedIPs     StringList `gorm:"type:text" json:"allowed_ips"`
	Endpoints      StringList `gorm:"type:text" json:"endpoints"` // reflexive/STUN public addresses
	IsActive       bool       `gorm:"default:true" json:"is_active"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`

	AssignedPoP *EdgePoP  `gorm:"foreignKey:AssignedPoPID" json:"assigned_pop,omitempty"`
	Tunnels     []Tunnel  `gorm:"foreignKey:NodeID" json:"tunnels,omitempty"`
}

// ACLAction represents whether to allow or drop traffic.
type ACLAction string

const (
	ACLActionAllow ACLAction = "ALLOW"
	ACLActionDeny  ACLAction = "DENY"
)

// ACLRule defines microsegmentation and access control within a network.
type ACLRule struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	NetworkID string    `gorm:"size:16;not null;index" json:"network_id"`
	Priority  int       `gorm:"default:100;not null" json:"priority"`
	SourceTag string    `gorm:"size:100;not null" json:"source_tag"` // e.g. "tag:web" or "*"
	DestTag   string    `gorm:"size:100;not null" json:"dest_tag"`   // e.g. "tag:db" or "*"
	Protocol  string    `gorm:"size:20;default:'*'" json:"protocol"` // "tcp", "udp", "icmp", "*"
	Ports     string    `gorm:"size:100;default:'*'" json:"ports"`   // "80,443", "5432", "*"
	Action    ACLAction `gorm:"size:20;default:'ALLOW'" json:"action"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Route defines subnet router advertisements inside the overlay mesh.
type Route struct {
	ID              uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	NetworkID       string    `gorm:"size:16;not null;index" json:"network_id"`
	NodeID          uuid.UUID `gorm:"type:uuid;not null;index" json:"node_id"`
	DestinationCIDR string    `gorm:"size:50;not null" json:"destination_cidr"` // e.g. "192.168.1.0/24"
	Metric          int       `gorm:"default:10" json:"metric"`
	IsAdvertised    bool      `gorm:"default:true" json:"is_advertised"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Tunnel defines a Cloudflared-style exposed service from a node to the mesh or gateway.
type Tunnel struct {
	ID             uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	NodeID         uuid.UUID `gorm:"type:uuid;not null;index" json:"node_id"`
	Name           string    `gorm:"size:100;not null" json:"name"`
	LocalAddress   string    `gorm:"size:100;not null" json:"local_address"`   // e.g. "127.0.0.1:8080"
	PublicHostname string    `gorm:"size:255;index" json:"public_hostname"` // e.g. "api.cubis.tech"
	Protocol       string    `gorm:"size:20;default:'http'" json:"protocol"`   // "http", "tcp", "grpc"
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// LatencySample represents a single latency probe result from a node to an Edge PoP.
type LatencySample struct {
	NodeID    uuid.UUID     `json:"node_id"`
	PoPCode   string        `json:"pop_code"`
	RTT       time.Duration `json:"rtt"`
	PacketLoss float64      `json:"packet_loss"`
	Timestamp time.Time     `json:"timestamp"`
}
