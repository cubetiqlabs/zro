package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cubetiqlabs/zro/pkg/identity"
	"github.com/cubetiqlabs/zro/pkg/update"
	"github.com/cubetiqlabs/zro/pkg/version"
	"github.com/spf13/cobra"
)

// clientCommands are the commands a person runs interactively or on a node;
// servers (plane, edge, gw) are upgraded by deployment, not nagged.
var clientCommands = map[string]bool{"node": true, "token": true, "network": true, "p2p": true, "version": true}

// notifyIfOutdated prints a one-line notice to stderr when a newer release
// exists. It checks GitHub at most once a day and is off with ZRO_NO_UPDATE_CHECK=1.
func notifyIfOutdated(cmd *cobra.Command) {
	if os.Getenv("ZRO_NO_UPDATE_CHECK") != "" {
		return
	}
	for cmd.HasParent() && cmd.Parent().HasParent() {
		cmd = cmd.Parent()
	}
	if !clientCommands[cmd.Name()] {
		return
	}
	if msg := update.Notice(context.Background(), identity.DefaultDir(), version.Version, time.Now()); msg != "" {
		fmt.Fprintln(os.Stderr, msg)
	}
}

func newUpdateCmd() *cobra.Command {
	var checkOnly bool
	var target string
	cmd := &cobra.Command{
		Use:          "update",
		Short:        "Update zro to the latest release (or --version vX.Y.Z)",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
			defer cancel()
			rel, err := update.Fetch(ctx, target)
			if err != nil {
				return fmt.Errorf("could not look up the release: %w", err)
			}
			if target == "" && !update.Newer(version.Version, rel.TagName) {
				fmt.Printf("zro %s is up to date.\n", version.Version)
				return nil
			}
			if checkOnly {
				fmt.Printf("zro %s is available (you have %s). Run `zro update`.\n", rel.TagName, version.Version)
				return nil
			}
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			if err := update.Apply(ctx, rel, exe); err != nil {
				return err
			}
			fmt.Printf("Updated zro %s -> %s. Restart any running zro services to use it.\n", version.Version, rel.TagName)
			return nil
		},
	}
	cmd.Flags().BoolVar(&checkOnly, "check", false, "Only report whether a newer release exists")
	cmd.Flags().StringVar(&target, "version", "", "Install this release tag instead of the latest (allows downgrades)")
	return cmd
}
