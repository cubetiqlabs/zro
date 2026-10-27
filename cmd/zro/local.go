package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"text/tabwriter"
	"time"

	"github.com/cubetiqlabs/zro/pkg/config"
	"github.com/cubetiqlabs/zro/pkg/node"
	"github.com/spf13/cobra"
)

// localCall talks to the running node through its admin socket.
func localCall(method, path string, out any) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}
	sock := node.AdminSocket(cfg.Node.StateDir)
	c := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}},
	}
	req, _ := http.NewRequest(method, "http://zro"+path, nil)
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("no running node at %s (is `zro join` running, as this user?): %w", sock, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct{ Error string }
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("%s", e.Error)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return time.Since(t).Round(time.Second).String() + " ago"
}

func newStatusCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show this node's mesh address, PoP and how each peer is reached",
		RunE: func(cmd *cobra.Command, args []string) error {
			var st node.Status
			if err := localCall(http.MethodGet, "/status", &st); err != nil {
				return err
			}
			if asJSON {
				return json.NewEncoder(os.Stdout).Encode(st)
			}
			fmt.Printf("%s  %s  network %s\nPoP %s (%s), handshake %s\n\n", st.Hostname, st.OverlayIPv4, st.NetworkID, st.PoP, st.PoPEndpoint, ago(st.PoPHandshake))
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "PEER\tIP\tPATH\tENDPOINT\tHANDSHAKE")
			for _, p := range st.Peers {
				ep := p.Endpoint
				if ep == "" {
					ep = "via " + st.PoP
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.Hostname, p.OverlayIPv4, p.Path, ep, ago(p.LastHandshake))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print JSON")
	return cmd
}

func newPingCmd() *cobra.Command {
	var count int
	cmd := &cobra.Command{
		Use:   "ping <peer-hostname|overlay-ip>",
		Short: "Ping a peer over the mesh and show the path used",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var failed int
			for i := 0; i < count; i++ {
				if i > 0 {
					time.Sleep(time.Second)
				}
				var r node.PingResult
				if err := localCall(http.MethodPost, "/ping?target="+url.QueryEscape(args[0]), &r); err != nil {
					fmt.Printf("%s: %v\n", args[0], err)
					failed++
					continue
				}
				fmt.Printf("pong from %s (%s) via %s in %.2fms\n", args[0], r.IP, r.Path, r.RTTMs)
			}
			if failed == count {
				return fmt.Errorf("no reply from %s", args[0])
			}
			return nil
		},
	}
	cmd.Flags().IntVarP(&count, "count", "n", 3, "Number of pings")
	return cmd
}
