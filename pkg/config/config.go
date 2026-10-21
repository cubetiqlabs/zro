package config

import (
	"fmt"
	"github.com/cubis/zro/pkg/identity"
	"reflect"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// AppConfig is the root configuration struct for all ZRO components.
type AppConfig struct {
	Mode         string             `mapstructure:"mode"`      // "plane", "edge", "node", "gw", "all"
	LogLevel     string             `mapstructure:"log_level"` // "debug", "info", "warn", "error"
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
	// gRPC transport security. Plaintext requires GRPCInsecure; GRPCTLSClientCA enables mTLS.
	GRPCTLSCert     string `mapstructure:"grpc_tls_cert"`
	GRPCTLSKey      string `mapstructure:"grpc_tls_key"`
	GRPCTLSClientCA string `mapstructure:"grpc_tls_client_ca"`
	GRPCInsecure    bool   `mapstructure:"grpc_insecure"`
	RequireAuth     bool   `mapstructure:"require_auth"`
	EdgeAPIKey      string `mapstructure:"edge_api_key"`
	// AdminAPIKey guards tenant administration; the tenant API is disabled when empty.
	AdminAPIKey string `mapstructure:"admin_api_key"`
	// NodeTTL is how long a node may stay silent before it is removed and its address freed; 0 disables reaping.
	NodeTTL time.Duration `mapstructure:"node_ttl"`
	// AllowedOrigins lists extra browser origins permitted to open event WebSockets (same-origin is always allowed).
	AllowedOrigins []string `mapstructure:"allowed_origins"`
}

// PlaneGRPC holds the gRPC client settings shared by every agent.
type PlaneGRPC struct {
	GRPCEndpoint string `mapstructure:"plane_grpc_endpoint"` // host:port of the plane's gRPC listener (defaults to plane_endpoint)
	GRPCInsecure bool   `mapstructure:"plane_grpc_insecure"` // plaintext gRPC; tokens then travel in clear text
	CAFile       string `mapstructure:"plane_ca_file"`       // optional CA bundle for the plane's TLS certificate
}

// EdgeConfig configures a global Edge Data Plane PoP.
type EdgeConfig struct {
	PoPCode             string `mapstructure:"pop_code"` // "KH", "SG", "US", "HK", "DE"
	Region              string `mapstructure:"region"`
	PublicEndpoint      string `mapstructure:"public_endpoint"` // "auto", "private", or "173.1.1.1:51820"
	ListenPort          int    `mapstructure:"listen_port"`
	InterfaceName       string `mapstructure:"interface_name"`
	MTU                 int    `mapstructure:"mtu"`
	WireGuardPrivateKey string `mapstructure:"wireguard_private_key"`
	StateDir            string `mapstructure:"state_dir"` // persists the edge identity; empty = ephemeral
	PlaneEndpoint       string `mapstructure:"plane_endpoint"`
	PlaneTransport      string `mapstructure:"plane_transport"` // "rest" or "grpc"
	PlaneGRPC           `mapstructure:",squash"`
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
	Hostname            string `mapstructure:"hostname"`
	StateDir            string `mapstructure:"state_dir"` // persists the WireGuard identity; empty = ephemeral
	NetworkID           string `mapstructure:"network_id"`
	EnrollmentToken     string `mapstructure:"enrollment_token"`
	PlaneEndpoint       string `mapstructure:"plane_endpoint"`
	PlaneTransport      string `mapstructure:"plane_transport"` // "rest" or "grpc"
	PlaneGRPC           `mapstructure:",squash"`
	InterfaceMode       string              `mapstructure:"interface_mode"` // "tun" or "netstack"
	InterfaceName       string              `mapstructure:"interface_name"` // "zro0"
	ListenPort          int                 `mapstructure:"listen_port"`    // shared UDP port; 0 = ephemeral
	MTU                 int                 `mapstructure:"mtu"`
	EnableP2P           bool                `mapstructure:"enable_p2p"`
	Tags                []string            `mapstructure:"tags"`
	AllowedInboundPorts []string            `mapstructure:"allowed_inbound_ports"` // e.g. ["5432/tcp"]
	DefaultDeny         bool                `mapstructure:"default_deny"`          // zero-trust default deny all
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
	Hostname              string `mapstructure:"hostname"`
	StateDir              string `mapstructure:"state_dir"` // persists the WireGuard identity; empty = ephemeral
	PlaneEndpoint         string `mapstructure:"plane_endpoint"`
	PlaneTransport        string `mapstructure:"plane_transport"` // "rest" or "grpc"
	PlaneGRPC             `mapstructure:",squash"`
	EnrollmentToken       string              `mapstructure:"enrollment_token"`
	NetworkID             string              `mapstructure:"network_id"`
	InterfaceName         string              `mapstructure:"interface_name"`
	InterfaceMode         string              `mapstructure:"interface_mode"` // "tun" (kernel) or "netstack" (unprivileged userspace)
	ListenPort            int                 `mapstructure:"listen_port"`    // shared UDP port; 0 = ephemeral
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
	v.SetDefault("control_plane.node_ttl", "168h")
	v.SetDefault("control_plane.grpc_listen_addr", "") // opt in; requires TLS or grpc_insecure

	// Edge defaults
	v.SetDefault("edge.state_dir", identity.DefaultDir())
	v.SetDefault("node.state_dir", identity.DefaultDir())
	v.SetDefault("gateway.state_dir", identity.DefaultDir())
	v.SetDefault("edge.pop_code", "KH")
	v.SetDefault("edge.region", "Asia/Phnom_Penh")
	v.SetDefault("edge.listen_port", 51820)
	v.SetDefault("edge.interface_name", "zro-edge")
	v.SetDefault("edge.mtu", 1420)
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
	// AutomaticEnv alone only reaches keys that already have a default or a file
	// entry, so bind every key explicitly or ZRO_EDGE_EDGE_API_KEY and friends
	// would be silently ignored when no config file is present.
	if err := bindEnv(v, reflect.TypeOf(AppConfig{}), ""); err != nil {
		return nil, err
	}

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

// bindEnv binds every leaf field of t to its environment variable, following
// the mapstructure tags (nested structs become dotted keys; ",squash" embeds).
func bindEnv(v *viper.Viper, t reflect.Type, prefix string) error {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, opts, _ := strings.Cut(f.Tag.Get("mapstructure"), ",")
		if name == "-" || !f.IsExported() {
			continue
		}
		key := name
		if prefix != "" && name != "" {
			key = prefix + "." + name
		}
		if opts == "squash" {
			key = prefix
		}
		if key == "" && opts != "squash" {
			continue
		}

		if f.Type.Kind() == reflect.Struct && f.Type != reflect.TypeOf(time.Duration(0)) {
			if err := bindEnv(v, f.Type, key); err != nil {
				return err
			}
			continue
		}
		if err := v.BindEnv(key); err != nil {
			return fmt.Errorf("binding %s: %w", key, err)
		}
	}
	return nil
}
