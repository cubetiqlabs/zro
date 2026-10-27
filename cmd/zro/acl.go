package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cubetiqlabs/zro/pkg/control/server"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

// planeAPI calls the control plane's tenant API.
type planeAPI struct{ plane, key, network string }

func (p planeAPI) do(method, path string, in, out any) error {
	if p.plane == "" || p.key == "" || p.network == "" {
		return fmt.Errorf("--plane, --api-key and --network are required (or $ZRO_PLANE, $ZRO_API_KEY, $ZRO_NETWORK)")
	}
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, strings.TrimRight(p.plane, "/")+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", p.key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return planeError(resp)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// planeError reads the plane's {"error": {"message": …}} body.
func planeError(resp *http.Response) error {
	var e struct {
		Error struct{ Message string } `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&e)
	return fmt.Errorf("control plane refused (%d): %s", resp.StatusCode, e.Error.Message)
}

func ruleSide(ip, tag string) string {
	switch {
	case ip != "*" && tag != "*":
		return ip + " " + tag
	case ip != "*":
		return ip
	}
	return tag
}

func newACLCmd() *cobra.Command {
	var api planeAPI
	cmd := &cobra.Command{
		Use:   "acl",
		Short: "Manage a network's access rules on the control plane",
		Long: `Manage a network's access rules on the control plane.

Rules name their ends with *, an IP, a CIDR, a tag (tag:web, role:db) or a node
hostname, and their ports with a service (ssh, https, postgres, ping…) or
"80,443/tcp". The lowest priority number wins; a DENY wins a tie. When no rule
matches, the destination node's own allow list and default_deny decide.`,
	}
	cmd.PersistentFlags().StringVar(&api.plane, "plane", os.Getenv("ZRO_PLANE"), "Control plane URL (default $ZRO_PLANE)")
	cmd.PersistentFlags().StringVar(&api.key, "api-key", os.Getenv("ZRO_API_KEY"), "Tenant API key (default $ZRO_API_KEY)")
	cmd.PersistentFlags().StringVar(&api.network, "network", os.Getenv("ZRO_NETWORK"), "Network ID (default $ZRO_NETWORK)")

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List the rules in evaluation order",
		RunE: func(cmd *cobra.Command, args []string) error {
			var rules []core.ACLRule
			cursor := ""
			for {
				var page server.Page[core.ACLRule]
				q := url.Values{"network_id": {api.network}, "cursor": {cursor}}
				if err := api.do(http.MethodGet, "/api/v1/acl/rules?"+q.Encode(), nil, &page); err != nil {
					return err
				}
				rules = append(rules, page.Items...)
				if cursor = page.NextCursor; cursor == "" {
					break
				}
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "PRIORITY\tACTION\tFROM\tTO\tPORTS\tNAME\tID")
			for _, r := range rules {
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s/%s\t%s\t%s\n", r.Priority, r.Action, ruleSide(r.SourceIP, r.SourceTag), ruleSide(r.DestIP, r.DestTag), r.Ports, r.Protocol, r.Name, r.ID)
			}
			return tw.Flush()
		},
	})

	var add server.CreateACLRuleRequest
	addCmd := &cobra.Command{
		Use:     "add",
		Short:   "Add a rule",
		Example: "  zro acl add --name 'web to db' --from tag:web --to db-1 --ports postgres\n  zro acl add --from tag:contractor --ports ssh --action deny --priority 5",
		RunE: func(cmd *cobra.Command, args []string) error {
			add.NetworkID = api.network
			var rule core.ACLRule
			if err := api.do(http.MethodPost, "/api/v1/acl/rules", add, &rule); err != nil {
				return err
			}
			fmt.Printf("Added rule %s: %s %s -> %s on %s/%s\n", rule.ID, rule.Action, ruleSide(rule.SourceIP, rule.SourceTag), ruleSide(rule.DestIP, rule.DestTag), rule.Ports, rule.Protocol)
			return nil
		},
	}
	addCmd.Flags().StringVar(&add.Name, "name", "", "Rule name")
	addCmd.Flags().StringVar(&add.From, "from", "*", "Source: *, IP, CIDR, tag or hostname")
	addCmd.Flags().StringVar(&add.To, "to", "*", "Destination: *, IP, CIDR, tag or hostname")
	addCmd.Flags().StringVar(&add.Ports, "ports", "*", "Service or ports: ssh, postgres, 80,443/tcp")
	addCmd.Flags().StringVar((*string)(&add.Action), "action", "allow", "allow or deny")
	addCmd.Flags().IntVar(&add.Priority, "priority", 100, "Lower is evaluated first")
	cmd.AddCommand(addCmd)

	cmd.AddCommand(&cobra.Command{
		Use:   "rm <rule-id>",
		Short: "Remove a rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := api.do(http.MethodDelete, "/api/v1/acl/rules/"+url.PathEscape(args[0]), nil, nil); err != nil {
				return err
			}
			fmt.Println("Removed", args[0])
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:     "test <from> <to> [port]",
		Short:   "Show whether the network rules let from reach to",
		Example: "  zro acl test web-1 db-1 postgres",
		Args:    cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := server.PolicyTestRequest{From: args[0], To: args[1]}
			if len(args) == 3 {
				req.Port = args[2]
			}
			var res server.PolicyTestResult
			if err := api.do(http.MethodPost, "/api/v1/networks/"+url.PathEscape(api.network)+"/policy/test", req, &res); err != nil {
				return err
			}
			switch res.Verdict {
			case "node-policy":
				fmt.Println("no rule matches: the destination node's own allow list and default_deny decide")
			default:
				name := res.Rule.Name
				if name == "" {
					name = res.Rule.ID.String()
				}
				fmt.Printf("%s (rule %q, priority %s)\n", strings.ToUpper(res.Verdict), name, strconv.Itoa(res.Rule.Priority))
			}
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "export",
		Short: "Print the whole policy as YAML (edit it, then zro acl apply -f)",
		RunE: func(cmd *cobra.Command, args []string) error {
			var doc server.PolicyDocument
			if err := api.do(http.MethodGet, "/api/v1/networks/"+url.PathEscape(api.network)+"/policy", nil, &doc); err != nil {
				return err
			}
			// Round-trip through JSON so the YAML keys match the API's.
			raw, _ := json.Marshal(doc)
			var generic any
			_ = json.Unmarshal(raw, &generic)
			return yaml.NewEncoder(os.Stdout).Encode(generic)
		},
	})

	var file string
	applyCmd := &cobra.Command{
		Use:   "apply -f policy.yaml",
		Short: "Replace the whole policy with a YAML or JSON file, atomically",
		Example: `  # policy.yaml
  rules:
    - {name: admins, from: "tag:admin", priority: 10}
    - {name: web to db, from: "tag:web", to: "tag:db", ports: postgres}
    - {name: no contractor ssh, from: "tag:contractor", ports: ssh, action: deny, priority: 5}`,
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			var doc any
			if err := yaml.Unmarshal(raw, &doc); err != nil {
				return fmt.Errorf("%s: %w", file, err)
			}
			var rules []core.ACLRule
			if err := api.do(http.MethodPut, "/api/v1/networks/"+url.PathEscape(api.network)+"/policy", doc, &rules); err != nil {
				return err
			}
			fmt.Printf("Applied %d rules to network %s\n", len(rules), api.network)
			return nil
		},
	}
	applyCmd.Flags().StringVarP(&file, "file", "f", "", "Policy file")
	_ = applyCmd.MarkFlagRequired("file")
	cmd.AddCommand(applyCmd)
	for _, c := range cmd.Commands() {
		c.SilenceUsage = true // a refused request is not a usage error
	}
	return cmd
}
