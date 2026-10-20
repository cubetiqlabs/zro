package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// AppConfig is the root configuration struct for all ZRO components.
type AppConfig struct {
	Mode         string             `mapstructure:"mode"`          // "plane", "edge", "node", "gw", "all"
	LogLevel     string             `mapstructure:"log_level"`     // "debug", "info", "warn", "error"
	ControlPlane ControlPlaneConfig `mapstructure:"control_plane"`
	Edge         EdgeConfig         `mapstructure:"edge"`
	Node         NodeConfig         `mapstructure:"node"`
	Gateway      GatewayConfig      `mapstructure:"gateway"`
}

// ControlPlaneConfig configures the zro-plane API server, IPAM, and database.
type ControlPlaneConfig struct {
	ListenAddr     string `mapstructure:"listen_addr"`
	PublicURL      string `mapstructure:"public_url"`
	DatabaseDriver string `mapstructure:"database_driver"` // "postgres" or "sqlite"
	DatabaseDSN    string `mapstructure:"database_dsn"`
	SecretKey      string `mapstructure:"secret_key"`
	DefaultCIDRv4  string `mapstructure:"default_cidr_v4"`
	DefaultCIDRv6  string `mapstructure:"default_cidr_v6"`
	SyncIntervalMs int    `mapstructure:"sync_interval_ms"`
	EnableGateway  bool   `mapstructure:"enable_gateway"`
	GRPCListenAddr string `mapstructure:"grpc_listen_addr"`
}

// EdgeConfig configures a global Edge Data Plane PoP.
type EdgeConfig struct {
	PoPCode             string `mapstructure:"pop_code"`        // "KH", "SG", "US", "HK", "DE"
	Region              string `mapstructure:"region"`
	PublicEndpoint      string `mapstructure:"public_endpoint"` // "auto", "private", or "173.1.1.1:51820"
	ListenPort          int    `mapstructure:"listen_port"`
	WireGuardPrivateKey string `mapstructure:"wireguard_private_key"`
	PlaneEndpoint       string `mapstructure:"plane_endpoint"`
	EdgeAPIKey          string `mapstructure:"edge_api_key"`
	IsAnycast           bool   `mapstructure:"is_anycast"`
	UsePrivateIP        bool   `mapstructure:"use_private_ip"`
}

// LocalTunnelConfig defines a service exposed by a node.
type LocalTunnelConfig struct {
	Name           string `mapstructure:"name"`
	LocalAddress   string `mapstructure:"local_address"`   // "127.0.0.1:8080"
	PublicHostname string `mapstructure:"public_hostname"` // "app.cubis.tech"
	Protocol       string `mapstructure:"protocol"`        // "http", "tcp", "grpc"
}

// NodeConfig configures the zro-node client daemon.
type NodeConfig struct {
	Hostname            string              `mapstructure:"hostname"`
	NetworkID           string              `mapstructure:"network_id"`
	EnrollmentToken     string              `mapstructure:"enrollment_token"`
	PlaneEndpoint       string              `mapstructure:"plane_endpoint"`
	InterfaceMode       string              `mapstructure:"interface_mode"` // "tun" or "netstack"
	InterfaceName       string              `mapstructure:"interface_name"` // "zro0"
	MTU                 int                 `mapstructure:"mtu"`
	EnableP2P           bool                `mapstructure:"enable_p2p"`
	Tags                []string            `mapstructure:"tags"`
	AllowedInboundPorts []string            `mapstructure:"allowed_inbound_ports"` // e.g. ["5432/tcp"]
	DefaultDeny         bool                `mapstructure:"default_deny"`           // zero-trust default deny all
	Tunnels             []LocalTunnelConfig `mapstructure:"tunnels"`
}

// StaticRouteConfig defines pre-configured upstream routes in zro.yaml.
type StaticRouteConfig struct {
	Hostname string   `mapstructure:"hostname"`
	Strategy string   `mapstructure:"strategy"` // "round_robin", "least_conn", "latency"
	Backends []string `mapstructure:"backends"` // e.g. ["100.64.0.10:3000", "100.64.0.11:3000"]
}

// GatewayConfig configures the reverse proxy and cloud-native load balancer.
type GatewayConfig struct {
	Hostname              string              `mapstructure:"hostname"`
	PlaneEndpoint         string              `mapstructure:"plane_endpoint"`
	EnrollmentToken       string              `mapstructure:"enrollment_token"`
	NetworkID             string              `mapstructure:"network_id"`
	InterfaceName         string              `mapstructure:"interface_name"`
	MTU                   int                 `mapstructure:"mtu"`
	Strategy              string              `mapstructure:"strategy"` // "round_robin", "least_conn", "latency"
	HealthCheckPath       string              `mapstructure:"health_check_path"`
	HealthCheckIntervalMs int                 `mapstructure:"health_check_interval_ms"`
	SyncIntervalMs        int                 `mapstructure:"sync_interval_ms"`
	ListenHTTP            string              `mapstructure:"listen_http"`
	ListenHTTPS           string              `mapstructure:"listen_https"`
	AutoTLS               bool                `mapstructure:"auto_tls"`
	Domain                string              `mapstructure:"domain"`
	CertDir               string              `mapstructure:"cert_dir"`
	DefaultPoP            string              `mapstructure:"default_pop"`
	StaticRoutes          []StaticRouteConfig `mapstructure:"static_routes"`
}

// Load loads configuration from an optional file path and merges with environment variables.
func Load(cfgFile string) (*AppConfig, error) {
	v := viper.New()

	// Defaults
	v.SetDefault("mode", "node")
	v.SetDefault("log_level", "info")

	// Control plane defaults
	v.SetDefault("control_plane.listen_addr", ":8443")
	v.SetDefault("control_plane.public_url", "https://zro-plane.cubis.tech:443")
	v.SetDefault("control_plane.database_driver", "sqlite")
	v.SetDefault("control_plane.database_dsn", "zro_control.db")
	v.SetDefault("control_plane.secret_key", "change-me-in-production-cluster-secret")
	v.SetDefault("control_plane.default_cidr_v4", "100.64.0.0/10")
	v.SetDefault("control_plane.default_cidr_v6", "fd00:cafe::/64")
	v.SetDefault("control_plane.sync_interval_ms", 1000)
	v.SetDefault("control_plane.enable_gateway", false)
	v.SetDefault("control_plane.grpc_listen_addr", ":9443")

	// Edge defaults
	v.SetDefault("edge.pop_code", "KH")
	v.SetDefault("edge.region", "Asia/Phnom_Penh")
	v.SetDefault("edge.listen_port", 51820)
	v.SetDefault("edge.public_endpoint", "auto")
	v.SetDefault("edge.use_private_ip", false)
	v.SetDefault("edge.plane_endpoint", "https://zro-plane.cubis.tech:443")
	v.SetDefault("edge.is_anycast", false)

	// Node defaults
	v.SetDefault("node.interface_mode", "tun")
	v.SetDefault("node.interface_name", "zro0")
	v.SetDefault("node.mtu", 1420)
	v.SetDefault("node.enable_p2p", true)
	v.SetDefault("node.default_deny", true)
	v.SetDefault("node.plane_endpoint", "https://zro-plane.cubis.tech:443")

	// Gateway defaults
	v.SetDefault("gateway.hostname", "gw1")
	v.SetDefault("gateway.plane_endpoint", "https://zro-plane.cubis.tech:443")
	v.SetDefault("gateway.interface_name", "zro-gw")
	v.SetDefault("gateway.mtu", 1420)
	v.SetDefault("gateway.strategy", "latency")
	v.SetDefault("gateway.health_check_path", "/health")
	v.SetDefault("gateway.health_check_interval_ms", 3000)
	v.SetDefault("gateway.sync_interval_ms", 3000)
	v.SetDefault("gateway.listen_http", ":80")
	v.SetDefault("gateway.listen_https", ":443")
	v.SetDefault("gateway.auto_tls", false)
	v.SetDefault("gateway.cert_dir", "./certs")

	// Environment variable overrides: ZRO_MODE, ZRO_CONTROL_PLANE_DATABASE_DSN, etc.
	v.SetEnvPrefix("ZRO")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config file %q: %w", cfgFile, err)
		}
	} else {
		// Look for zro.yaml in local directory or /etc/zro
		v.SetConfigName("zro")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("/etc/zro")
		_ = v.ReadInConfig() // ignore missing default file, will rely on defaults and env
	}

	var cfg AppConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	return &cfg, nil
}
