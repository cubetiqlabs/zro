package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/cubetiqlabs/zro/pkg/control/server"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/spf13/cobra"
)

// planeFlags adds the tenant API flags shared by zro acl, nodes and audit.
// With needNetwork, every subcommand requires --network.
func planeFlags(cmd *cobra.Command, api *planeAPI, needNetwork bool) {
	if needNetwork {
		cmd.PersistentPreRunE = func(*cobra.Command, []string) error {
			if api.network == "" {
				return fmt.Errorf("--network is required (or $ZRO_NETWORK)")
			}
			return nil
		}
	}
	cmd.PersistentFlags().StringVar(&api.plane, "plane", os.Getenv("ZRO_PLANE"), "Control plane URL (default $ZRO_PLANE)")
	cmd.PersistentFlags().StringVar(&api.key, "api-key", os.Getenv("ZRO_API_KEY"), "Tenant API key (default $ZRO_API_KEY)")
	cmd.PersistentFlags().StringVar(&api.network, "network", os.Getenv("ZRO_NETWORK"), "Network ID (default $ZRO_NETWORK)")
}

func (p planeAPI) nodes() ([]core.Node, error) {
	var all []core.Node
	cursor := ""
	for {
		var page server.Page[core.Node]
		q := url.Values{"network_id": {p.network}, "cursor": {cursor}}
		if err := p.do(http.MethodGet, "/api/v1/nodes?"+q.Encode(), nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Items...)
		if cursor = page.NextCursor; cursor == "" {
			return all, nil
		}
	}
}

// nodeID accepts a node ID, hostname or overlay IP.
func (p planeAPI) nodeID(ref string) (string, error) {
	nodes, err := p.nodes()
	if err != nil {
		return "", err
	}
	for _, n := range nodes {
		if n.ID.String() == ref || n.Hostname == ref || n.OverlayIPv4 == ref {
			return n.ID.String(), nil
		}
	}
	return "", fmt.Errorf("no node %q in network %s", ref, p.network)
}

func nodeState(n core.Node) string {
	switch {
	case n.Disabled:
		return "disabled"
	case n.Pending:
		return "pending"
	case n.Expired(time.Now()):
		return "expired"
	case time.Since(n.LastSeenAt) < 2*time.Minute:
		return "online"
	}
	return "offline"
}

func newNodesCmd() *cobra.Command {
	var api planeAPI
	cmd := &cobra.Command{Use: "nodes", Short: "Manage a network's nodes on the control plane (list, approve, tag, disable, remove)"}
	planeFlags(cmd, &api, true)

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List nodes with their state and tags",
		RunE: func(cmd *cobra.Command, args []string) error {
			nodes, err := api.nodes()
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "HOSTNAME\tIP\tSTATE\tTYPE\tTAGS\tLAST SEEN\tID")
			for _, n := range nodes {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", n.Hostname, n.OverlayIPv4, nodeState(n), n.NodeType, strings.Join(n.Tags, ","), ago(n.LastSeenAt), n.ID)
			}
			return tw.Flush()
		},
	})

	// act runs one change against the node named by args[0].
	act := func(use, short string, args cobra.PositionalArgs, run func(id string, args []string) error) *cobra.Command {
		return &cobra.Command{
			Use: use, Short: short, Args: args, SilenceUsage: true,
			RunE: func(cmd *cobra.Command, args []string) error {
				id, err := api.nodeID(args[0])
				if err != nil {
					return err
				}
				if err := run(id, args[1:]); err != nil {
					return err
				}
				fmt.Printf("%s: done\n", args[0])
				return nil
			},
		}
	}
	patch := func(id string, body any) error {
		return api.do(http.MethodPatch, "/api/v1/nodes/"+id, body, nil)
	}
	cmd.AddCommand(
		act("approve <node>", "Admit a node held for approval", cobra.ExactArgs(1), func(id string, _ []string) error {
			return api.do(http.MethodPost, "/api/v1/nodes/"+id+"/approve", nil, nil)
		}),
		act("tag <node> <tag>...", "Set a node's tags (they then win over the node's own)", cobra.MinimumNArgs(2), func(id string, tags []string) error {
			return patch(id, map[string]any{"tags": tags})
		}),
		act("disable <node>", "Cut a node off the mesh; it cannot reconnect until enabled", cobra.ExactArgs(1), func(id string, _ []string) error {
			return patch(id, map[string]any{"disabled": true})
		}),
		act("enable <node>", "Let a disabled node back in", cobra.ExactArgs(1), func(id string, _ []string) error {
			return patch(id, map[string]any{"disabled": false})
		}),
		act("rm <node>", "Remove a node and free its address", cobra.ExactArgs(1), func(id string, _ []string) error {
			return api.do(http.MethodDelete, "/api/v1/nodes/"+id, nil, nil)
		}),
	)
	for _, c := range cmd.Commands() {
		c.SilenceUsage = true
	}
	return cmd
}

func newAuditCmd() *cobra.Command {
	var api planeAPI
	var limit int
	var all bool
	cmd := &cobra.Command{
		Use:          "audit",
		Short:        "Show who changed what on the control plane, newest first",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			q := url.Values{"limit": {fmt.Sprint(limit)}}
			if !all {
				if api.network == "" {
					return fmt.Errorf("--network is required (or --all for every network of the tenant)")
				}
				q.Set("network_id", api.network)
			}
			var events []core.AuditEvent
			if err := api.do(http.MethodGet, "/api/v1/audit?"+q.Encode(), nil, &events); err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "TIME\tACTOR\tACTION\tTARGET\tDETAIL\tFROM")
			for _, e := range events {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", e.CreatedAt.Local().Format(time.DateTime), e.Actor, e.Action, e.Target, e.Detail, e.SourceIP)
			}
			return tw.Flush()
		},
	}
	planeFlags(cmd, &api, false)
	cmd.Flags().IntVarP(&limit, "limit", "n", 50, "Number of events")
	cmd.Flags().BoolVar(&all, "all", false, "Every network of the tenant, plus tenant-level events")
	return cmd
}
