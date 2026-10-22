package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cubetiqlabs/zro/pkg/config"
	"github.com/cubetiqlabs/zro/pkg/control/server"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/cubetiqlabs/zro/pkg/crypto"
	"github.com/cubetiqlabs/zro/pkg/edge"
	"github.com/cubetiqlabs/zro/pkg/gateway"
	"github.com/cubetiqlabs/zro/pkg/node"
	"github.com/cubetiqlabs/zro/pkg/store"
	"github.com/cubetiqlabs/zro/pkg/version"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use:              "zro",
		PersistentPreRun: func(cmd *cobra.Command, args []string) { notifyIfOutdated(cmd) },
		Short:            "ZRO: High-Performance Global Networking & Ether-Switch Mesh",
		Long: `ZRO is an enterprise-grade global networking fabric with userspace WireGuard,
smart routing, IPless nodes, zero-trust ACLs, and cloud-native load balancing.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

			mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
			switch mode {
			case "plane", "control_plane":
				return runPlane(cfg)
			case "edge":
				return runEdge(cfg)
			case "node":
				return runNode(cfg)
			case "gw", "gateway":
				return runGateway(cfg)
			default:
				if mode != "" {
					return fmt.Errorf("unknown mode %q in configuration (expected: plane, edge, node, gw)", mode)
				}
				return cmd.Help()
			}
		},
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Path to configuration file (default: ./zro.yaml)")

	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newPlaneCmd())
	rootCmd.AddCommand(newEdgeCmd())
	rootCmd.AddCommand(newNodeCmd())
	rootCmd.AddCommand(newGatewayCmd())
	rootCmd.AddCommand(newKeygenCmd())
	rootCmd.AddCommand(newTokenCmd())
	rootCmd.AddCommand(newNetworkCmd())
	rootCmd.AddCommand(newP2PCmd())
	rootCmd.AddCommand(newUpdateCmd())
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runPlane(cfg *config.AppConfig) error {
	slog.Info("ZRO control plane", "build", version.Get())
	slog.Info("Initializing Control Plane database", "driver", cfg.ControlPlane.DatabaseDriver)
	db, err := store.NewDB(cfg.ControlPlane.DatabaseDriver, cfg.ControlPlane.DatabaseDSN)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	srv := server.NewServer(&cfg.ControlPlane, db)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
			slog.Error("Control Plane error", "error", err)
		}
	}()

	<-ctx.Done()
	slog.Info("Shutting down Control Plane gracefully...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func runEdge(cfg *config.AppConfig) error {
	pop, err := edge.NewPoPDaemon(&cfg.Edge)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := pop.Start(ctx); err != nil {
		return err
	}

	<-ctx.Done()
	slog.Info("Shutting down Edge PoP...")
	return pop.Stop()
}

func runNode(cfg *config.AppConfig) error {
	agent, err := node.NewDaemon(&cfg.Node)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := agent.Start(ctx); err != nil {
		return err
	}

	<-ctx.Done()
	slog.Info("Disconnecting node from overlay mesh...")
	return agent.Stop()
}

func runGateway(cfg *config.AppConfig) error {
	gwDaemon, err := gateway.NewDaemon(&cfg.Gateway)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := gwDaemon.Start(ctx); err != nil {
		return err
	}

	<-ctx.Done()
	slog.Info("Stopping Ingress Gateway...")
	return gwDaemon.Stop()
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the build version",
		Run:   func(cmd *cobra.Command, args []string) { fmt.Println(version.Get()) },
	}
}

func newPlaneCmd() *cobra.Command {
	var enableGatewayFlag bool

	cmd := &cobra.Command{
		Use:   "plane",
		Short: "Run the ZRO Control Plane API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

			if enableGatewayFlag {
				cfg.ControlPlane.EnableGateway = true
			}

			return runPlane(cfg)
		},
	}

	cmd.Flags().BoolVar(&enableGatewayFlag, "enable-gateway", false, "Enable in-process Ingress Gateway on Control Plane")
	return cmd
}

func newEdgeCmd() *cobra.Command {
	var endpointFlag, popCodeFlag, planeFlag string
	var listenPortFlag int
	var usePrivateIPFlag bool

	cmd := &cobra.Command{
		Use:   "edge",
		Short: "Run the ZRO Edge Data Plane PoP",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

			if endpointFlag != "" {
				cfg.Edge.PublicEndpoint = endpointFlag
			}
			if usePrivateIPFlag {
				cfg.Edge.UsePrivateIP = true
			}
			if listenPortFlag > 0 {
				cfg.Edge.ListenPort = listenPortFlag
			}
			if popCodeFlag != "" {
				cfg.Edge.PoPCode = popCodeFlag
			}
			if planeFlag != "" {
				cfg.Edge.PlaneEndpoint = planeFlag
			}

			return runEdge(cfg)
		},
	}

	cmd.Flags().StringVar(&endpointFlag, "endpoint", "", "Edge public/private endpoint ('auto', 'private', or host:port)")
	cmd.Flags().BoolVar(&usePrivateIPFlag, "private-ip", false, "Force using local private IP for internal/standalone testing")
	cmd.Flags().IntVarP(&listenPortFlag, "port", "p", 0, "Edge UDP listen port")
	cmd.Flags().StringVar(&popCodeFlag, "pop-code", "", "Edge PoP code (e.g. KH, SG, US)")
	cmd.Flags().StringVar(&planeFlag, "plane", "", "Control Plane API URL")
	return cmd
}

func newNodeCmd() *cobra.Command {
	var planeFlag, tokenFlag, hostnameFlag string
	var netstack bool

	cmd := &cobra.Command{
		Use:     "node",
		Aliases: []string{"join"},
		Short:   "Join the mesh: zro join --plane URL --token TOKEN",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}
			if planeFlag != "" {
				cfg.Node.PlaneEndpoint = planeFlag
			}
			if tokenFlag != "" {
				cfg.Node.EnrollmentToken = tokenFlag
			}
			if hostnameFlag != "" {
				cfg.Node.Hostname = hostnameFlag
			}
			if netstack {
				cfg.Node.InterfaceMode = "netstack"
			}
			if cfg.Node.Hostname == "" {
				cfg.Node.Hostname, _ = os.Hostname()
			}

			return runNode(cfg)
		},
	}
	cmd.Flags().StringVar(&planeFlag, "plane", "", "Control Plane API URL")
	cmd.Flags().StringVar(&tokenFlag, "token", "", "Enrollment token (from the operator)")
	cmd.Flags().StringVar(&hostnameFlag, "hostname", "", "Node name (default: this machine's hostname)")
	cmd.Flags().BoolVar(&netstack, "netstack", false, "Run unprivileged: no TUN device or root needed")
	return cmd
}

func newGatewayCmd() *cobra.Command {
	var planeFlag, tokenFlag, hostnameFlag string
	var listenHTTPFlag, listenHTTPSFlag string

	cmd := &cobra.Command{
		Use:   "gw",
		Short: "Run the Cloud-Native Ingress Gateway and Load Balancer",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

			if planeFlag != "" {
				cfg.Gateway.PlaneEndpoint = planeFlag
			}
			if tokenFlag != "" {
				cfg.Gateway.EnrollmentToken = tokenFlag
			}
			if hostnameFlag != "" {
				cfg.Gateway.Hostname = hostnameFlag
			}
			if listenHTTPFlag != "" {
				cfg.Gateway.ListenHTTP = listenHTTPFlag
			}
			if listenHTTPSFlag != "" {
				cfg.Gateway.ListenHTTPS = listenHTTPSFlag
			}

			return runGateway(cfg)
		},
	}

	cmd.Flags().StringVar(&planeFlag, "plane", "", "Control Plane API URL")
	cmd.Flags().StringVar(&tokenFlag, "token", "", "Enrollment token")
	cmd.Flags().StringVar(&hostnameFlag, "hostname", "", "Gateway hostname")
	cmd.Flags().StringVar(&listenHTTPFlag, "listen-http", "", "HTTP listen address")
	cmd.Flags().StringVar(&listenHTTPSFlag, "listen-https", "", "HTTPS listen address")
	return cmd
}

func newKeygenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keygen",
		Short: "Generate a new WireGuard Curve25519 keypair",
		RunE: func(cmd *cobra.Command, args []string) error {
			kp, err := crypto.GenerateKeyPair()
			if err != nil {
				return err
			}
			fmt.Printf("Private Key: %s\n", kp.PrivateKey)
			fmt.Printf("Public Key:  %s\n", kp.PublicKey)
			return nil
		},
	}
}

func newTokenCmd() *cobra.Command {
	var secret string
	var networkID string
	var hostname string
	var pubKey, nodeType string
	var durationHours int
	var planeURL, apiKey string

	cmd := &cobra.Command{
		Use:   "token",
		Short: "Generate a signed node enrollment token with public key binding",
		RunE: func(cmd *cobra.Command, args []string) error {
			if apiKey != "" {
				return mintViaPlane(planeURL, apiKey, networkID, hostname, nodeType, pubKey, durationHours)
			}
			if secret == "" {
				secret = secretDefault()
			}
			if networkID == "" {
				return fmt.Errorf("--secret and --network-id flags are required")
			}
			tok, err := crypto.SignEnrollmentToken(secret, crypto.EnrollmentTokenPayload{
				NetworkID:      networkID,
				Hostname:       hostname,
				NodeType:       nodeType,
				BoundPublicKey: pubKey,
				Expiry:         time.Now().Add(time.Duration(durationHours) * time.Hour).Unix(),
			})
			if err != nil {
				return err
			}
			fmt.Printf("Enrollment Token:\n%s\n", tok)
			return nil
		},
	}

	cmd.Flags().StringVar(&secret, "secret", "", "Cluster secret key (default $ZRO_CONTROL_PLANE_SECRET_KEY)")
	cmd.Flags().StringVar(&nodeType, "type", "peer", "Node role the token may enroll as: peer or gateway")
	cmd.Flags().StringVar(&networkID, "network-id", "8056c2e21c000001", "Target 16-hex Network ID")
	cmd.Flags().StringVar(&hostname, "hostname", "", "Lock the token to this node name (default: any)")
	cmd.Flags().StringVar(&pubKey, "pubkey", "", "Optional WireGuard public key to bind cryptographically")
	cmd.Flags().IntVar(&durationHours, "hours", 24, "Validity duration in hours")
	cmd.Flags().StringVar(&planeURL, "plane", "", "Mint through this control plane instead of signing locally")
	cmd.Flags().StringVar(&apiKey, "api-key", os.Getenv("ZRO_API_KEY"), "Tenant API key (default $ZRO_API_KEY); no cluster secret needed")
	return cmd
}

// mintViaPlane asks the control plane for a token, so operators need only
// their tenant API key.
func mintViaPlane(plane, apiKey, networkID, hostname, nodeType, pubKey string, hours int) error {
	if plane == "" {
		return fmt.Errorf("--plane is required with --api-key")
	}
	body, _ := json.Marshal(map[string]any{"hostname": hostname, "node_type": nodeType, "pubkey": pubKey, "hours": hours})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(plane, "/")+"/api/v1/networks/"+networkID+"/tokens", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var out struct {
		JoinCommand string `json:"join_command"`
		Token       string `json:"token"`
		Error       string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("control plane refused (%d): %s", resp.StatusCode, out.Error)
	}
	fmt.Printf("Enrollment Token:\n%s\n\nRun on the new machine:\n  %s\n", out.Token, out.JoinCommand)
	return nil
}

func secretDefault() string {
	if v := os.Getenv("ZRO_CONTROL_PLANE_SECRET_KEY"); v != "" {
		return v
	}
	return crypto.DefaultSecretKey
}

func newNetworkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Manage ZRO overlay networks (ZeroTier-styled 16-hex IDs)",
	}

	var name, cidrv4, cidrv6, planeURL, apiKey string
	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new overlay network",
		RunE: func(cmd *cobra.Command, args []string) error {
			netReq := map[string]string{
				"name":      name,
				"ipv4_cidr": cidrv4,
				"ipv6_cidr": cidrv6,
			}
			body, _ := json.Marshal(netReq)
			resp, err := postJSON(planeURL+"/api/v1/networks", apiKey, body)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				return fmt.Errorf("failed to create network: status %d", resp.StatusCode)
			}
			var net core.Network
			_ = json.NewDecoder(resp.Body).Decode(&net)
			fmt.Printf("Created Network Successfully!\n")
			fmt.Printf("Network ID:  %s (ZeroTier-style 16-hex)\n", net.ID)
			fmt.Printf("Name:        %s\n", net.Name)
			fmt.Printf("IPv4 CIDR:   %s\n", net.IPv4CIDR)
			fmt.Printf("IPv6 CIDR:   %s\n", net.IPv6CIDR)
			return nil
		},
	}
	createCmd.Flags().StringVar(&name, "name", "My Mesh Network", "Network name")
	createCmd.Flags().StringVar(&cidrv4, "cidr", "100.64.0.0/10", "IPv4 CIDR overlay space")
	createCmd.Flags().StringVar(&cidrv6, "cidr-v6", "fd00:cafe::/64", "IPv6 CIDR overlay space")
	createCmd.Flags().StringVar(&planeURL, "plane", "http://localhost:8443", "Control Plane URL")
	createCmd.Flags().StringVar(&apiKey, "api-key", os.Getenv("ZRO_API_KEY"), "Tenant API key (default $ZRO_API_KEY)")

	cmd.AddCommand(createCmd)
	return cmd
}

func newP2PCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "p2p",
		Short: "P2P discovery, NAT traversal, and smart routing coordination",
	}

	var planeURL, nodeIDStr, nodeToken string
	discoverCmd := &cobra.Command{
		Use:   "discover <target_overlay_ip>",
		Short: "Perform P2P discovery & coordinate direct hole punch to target",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetIP := args[0]
			var nodeID uuid.UUID
			if nodeIDStr != "" {
				var err error
				if nodeID, err = uuid.Parse(nodeIDStr); err != nil {
					return fmt.Errorf("invalid --node-id: %w", err)
				}
			}
			if nodeToken == "" {
				return fmt.Errorf("--node-token or $ZRO_NODE_TOKEN is required")
			}

			discReq := server.P2PDiscoverRequest{
				InitiatorNodeID: nodeID,
				TargetOverlayIP: targetIP,
			}
			body, _ := json.Marshal(discReq)
			resp, err := postJSON(planeURL+"/api/v1/p2p/discover", nodeToken, body)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("p2p discovery failed with status %d", resp.StatusCode)
			}

			var discResp server.P2PDiscoverResponse
			_ = json.NewDecoder(resp.Body).Decode(&discResp)

			fmt.Println("P2P Discovery Successful!")
			fmt.Printf("Target Hostname:  %s\n", discResp.TargetHostname)
			fmt.Printf("Target Node ID:   %s\n", discResp.TargetNodeID)
			fmt.Printf("Overlay IPv4:     %s\n", discResp.TargetOverlayIPv4)
			fmt.Printf("Public Key:       %s\n", discResp.TargetPublicKey)
			fmt.Printf("NAT Endpoints:    %v\n", discResp.TargetEndpoints)
			if discResp.PrimaryPoP != nil {
				fmt.Printf("Relay Fallback:   Edge %s (%s)\n", discResp.PrimaryPoP.PoPCode, discResp.PrimaryPoP.PublicEndpoint)
			}
			return nil
		},
	}
	discoverCmd.Flags().StringVar(&planeURL, "plane", "http://localhost:8443", "Control Plane URL")
	discoverCmd.Flags().StringVar(&nodeIDStr, "node-id", "", "Initiator Node UUID (optional; the token identifies the node)")
	discoverCmd.Flags().StringVar(&nodeToken, "node-token", os.Getenv("ZRO_NODE_TOKEN"), "Node token issued at enrollment (default $ZRO_NODE_TOKEN)")
	_ = discoverCmd.MarkFlagRequired("node-id")

	cmd.AddCommand(discoverCmd)
	return cmd
}

// postJSON sends an authenticated JSON POST to the control plane.
func postJSON(url, bearer string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return http.DefaultClient.Do(req)
}
