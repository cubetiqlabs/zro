package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cubis/zro/pkg/config"
	"github.com/cubis/zro/pkg/control/server"
	"github.com/cubis/zro/pkg/crypto"
	"github.com/cubis/zro/pkg/edge"
	"github.com/cubis/zro/pkg/gateway/balancer"
	"github.com/cubis/zro/pkg/gateway/proxy"
	"github.com/cubis/zro/pkg/node"
	"github.com/cubis/zro/pkg/store"
	"github.com/google/uuid"
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
	var durationHours int

	cmd := &cobra.Command{
		Use:   "token",
		Short: "Generate a signed node enrollment token",
		RunE: func(cmd *cobra.Command, args []string) error {
			if secret == "" || networkID == "" || hostname == "" {
				return fmt.Errorf("--secret, --network-id, and --hostname flags are required")
			}
			tok := crypto.GenerateEnrollmentToken(secret, networkID, hostname, time.Duration(durationHours)*time.Hour)
			fmt.Printf("Enrollment Token:\n%s\n", tok)
			return nil
		},
	}

	cmd.Flags().StringVar(&secret, "secret", "change-me-in-production-cluster-secret", "Cluster secret key")
	cmd.Flags().StringVar(&networkID, "network-id", uuid.New().String(), "Target Network UUID")
	cmd.Flags().StringVar(&hostname, "hostname", "my-node", "Node hostname")
	cmd.Flags().IntVar(&durationHours, "hours", 24, "Validity duration in hours")
	return cmd
}
