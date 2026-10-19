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
	"syscall"
	"time"

	"github.com/cubis/zro/pkg/config"
	"github.com/cubis/zro/pkg/control/server"
	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/crypto"
	"github.com/cubis/zro/pkg/edge"
	"github.com/cubis/zro/pkg/gateway/acme"
	"github.com/cubis/zro/pkg/gateway/balancer"
	"github.com/cubis/zro/pkg/gateway/proxy"
	"github.com/cubis/zro/pkg/node"
	"github.com/cubis/zro/pkg/store"
	"github.com/cubis/zro/pkg/tunnel"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use:   "zro",
		Short: "ZRO: High-Performance Global Networking & Ether-Switch Mesh",
		Long: `ZRO is an enterprise-grade global networking fabric with userspace WireGuard,
smart routing, IPless nodes, zero-trust ACLs, and cloud-native load balancing.`,
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Path to configuration file (default: ./zro.yaml)")

	rootCmd.AddCommand(newPlaneCmd())
	rootCmd.AddCommand(newEdgeCmd())
	rootCmd.AddCommand(newNodeCmd())
	rootCmd.AddCommand(newGatewayCmd())
	rootCmd.AddCommand(newKeygenCmd())
	rootCmd.AddCommand(newTokenCmd())
	rootCmd.AddCommand(newNetworkCmd())
	rootCmd.AddCommand(newSocksCmd())
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newPlaneCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "plane",
		Short: "Run the ZRO Control Plane API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

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
		},
	}
}

func newEdgeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "edge",
		Short: "Run the ZRO Edge Data Plane PoP",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

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
		},
	}
}

func newNodeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "node",
		Short: "Run the ZRO Client / Peer Agent Daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

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
		},
	}
}

func newGatewayCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "gw",
		Short: "Run the Cloud-Native Ingress Gateway and Load Balancer",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

			proxyEngine := proxy.NewEngine()

			// Configure test reverse proxy route if specified
			if cfg.Gateway.Domain != "" {
				backends := []*balancer.Backend{
					{Address: "127.0.0.1:8080", Healthy: true, Weight: 10},
				}
				bal := balancer.NewBalancer(balancer.StrategyRoundRobin, backends)
				proxyEngine.RegisterRoute(cfg.Gateway.Domain, bal)
			}

			// Automated ACME TLS termination if enabled
			if cfg.Gateway.AutoTLS && cfg.Gateway.Domain != "" {
				acmeMgr, err := acme.NewManager(acme.Config{
					Enabled: true,
					Domains: []string{cfg.Gateway.Domain},
					CertDir: cfg.Gateway.CertDir,
				})
				if err == nil {
					httpsServer := &http.Server{
						Addr:         cfg.Gateway.ListenHTTPS,
						Handler:      proxyEngine,
						TLSConfig:    acmeMgr.TLSConfig(),
						ReadTimeout:  15 * time.Second,
						WriteTimeout: 15 * time.Second,
					}
					go func() {
						slog.Info("ZRO Ingress Gateway HTTPS listening with AutoTLS", "addr", cfg.Gateway.ListenHTTPS, "domain", cfg.Gateway.Domain)
						_ = httpsServer.ListenAndServeTLS("", "")
					}()
				}
			}

			httpServer := &http.Server{
				Addr:         cfg.Gateway.ListenHTTP,
				Handler:      proxyEngine,
				ReadTimeout:  15 * time.Second,
				WriteTimeout: 15 * time.Second,
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			go func() {
				slog.Info("ZRO Ingress Gateway listening", "addr", cfg.Gateway.ListenHTTP)
				if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					slog.Error("Gateway server error", "error", err)
				}
			}()

			<-ctx.Done()
			slog.Info("Stopping Ingress Gateway...")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return httpServer.Shutdown(shutdownCtx)
		},
	}
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
	var pubKey string
	var durationHours int

	cmd := &cobra.Command{
		Use:   "token",
		Short: "Generate a signed node enrollment token with public key binding",
		RunE: func(cmd *cobra.Command, args []string) error {
			if secret == "" || networkID == "" || hostname == "" {
				return fmt.Errorf("--secret, --network-id, and --hostname flags are required")
			}
			tok := crypto.GenerateEnrollmentToken(secret, networkID, hostname, time.Duration(durationHours)*time.Hour, pubKey)
			fmt.Printf("Enrollment Token:\n%s\n", tok)
			return nil
		},
	}

	cmd.Flags().StringVar(&secret, "secret", "change-me-in-production-cluster-secret", "Cluster secret key")
	cmd.Flags().StringVar(&networkID, "network-id", "8056c2e21c000001", "Target 16-hex Network ID")
	cmd.Flags().StringVar(&hostname, "hostname", "my-node", "Node hostname")
	cmd.Flags().StringVar(&pubKey, "pubkey", "", "Optional WireGuard public key to bind cryptographically")
	cmd.Flags().IntVar(&durationHours, "hours", 24, "Validity duration in hours")
	return cmd
}

func newNetworkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Manage ZRO overlay networks (ZeroTier-styled 16-hex IDs)",
	}

	var name, cidrv4, cidrv6, planeURL string
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
			resp, err := http.Post(planeURL+"/api/v1/networks", "application/json", bytes.NewReader(body))
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

	cmd.AddCommand(createCmd)
	return cmd
}

func newSocksCmd() *cobra.Command {
	var listenAddr string
	cmd := &cobra.Command{
		Use:   "socks",
		Short: "Run the built-in SOCKS5 proxy server for tunneling any application",
		RunE: func(cmd *cobra.Command, args []string) error {
			srv := tunnel.NewSOCKS5Server(nil)
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			go func() {
				if err := srv.ListenAndServe(listenAddr); err != nil && err != http.ErrServerClosed {
					slog.Error("SOCKS5 server error", "error", err)
				}
			}()

			<-ctx.Done()
			slog.Info("Stopping SOCKS5 server...")
			return srv.Close()
		},
	}
	cmd.Flags().StringVarP(&listenAddr, "listen", "l", ":1080", "Listen address for SOCKS5 proxy")
	return cmd
}
