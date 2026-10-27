package main

import (
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/spf13/cobra"
)

func newKeyCmd() *cobra.Command {
	var api planeAPI
	cmd := &cobra.Command{Use: "key", Short: "Manage scoped tenant API keys (needs an admin key)"}
	planeFlags(cmd, &api, false)

	var name, scope string
	var hours int
	create := &cobra.Command{
		Use:     "create",
		Short:   "Create a key; it is shown once",
		Example: "  zro key create --name ci --scope write --hours 720\n  zro key create --name grafana --scope read",
		RunE: func(cmd *cobra.Command, args []string) error {
			var out struct {
				core.APIKey
				Key string `json:"key"`
			}
			if err := api.do(http.MethodPost, "/api/v1/keys", map[string]any{"name": name, "scope": scope, "expires_in_hours": hours}, &out); err != nil {
				return err
			}
			fmt.Printf("Created %s key %q (%s). Store it now; it is not shown again:\n%s\n", out.Scope, out.Name, out.ID, out.Key)
			return nil
		},
	}
	create.Flags().StringVar(&name, "name", "", "What the key is for")
	create.Flags().StringVar(&scope, "scope", core.ScopeRead, "read, write or admin")
	create.Flags().IntVar(&hours, "hours", 0, "Expire after this many hours (0 = never)")
	_ = create.MarkFlagRequired("name")

	list := &cobra.Command{
		Use:   "list",
		Short: "List keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			var keys []core.APIKey
			if err := api.do(http.MethodGet, "/api/v1/keys", nil, &keys); err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tSCOPE\tEXPIRES\tLAST USED\tID")
			for _, k := range keys {
				exp, used := "never", "-"
				if k.ExpiresAt != nil {
					exp = k.ExpiresAt.Local().Format("2006-01-02 15:04")
				}
				if k.LastUsedAt != nil {
					used = ago(*k.LastUsedAt)
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", k.Name, k.Scope, exp, used, k.ID)
			}
			return tw.Flush()
		},
	}
	rm := &cobra.Command{
		Use:   "rm <key-id>",
		Short: "Revoke a key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := api.do(http.MethodDelete, "/api/v1/keys/"+args[0], nil, nil); err != nil {
				return err
			}
			fmt.Println("Revoked", args[0])
			return nil
		},
	}
	cmd.AddCommand(create, list, rm)
	for _, c := range cmd.Commands() {
		c.SilenceUsage = true
	}
	return cmd
}
