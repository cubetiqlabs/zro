package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cubetiqlabs/zro/pkg/config"
	"github.com/cubetiqlabs/zro/pkg/node"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

// daemonSigner signs with the node's SSH key through the admin socket, so the
// private key never leaves the daemon.
type daemonSigner struct{ pub ssh.PublicKey }

func (s daemonSigner) PublicKey() ssh.PublicKey { return s.pub }

func (s daemonSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	var sig ssh.Signature
	return &sig, localCallBody(http.MethodPost, "/ssh/sign", bytes.NewReader(data), &sig)
}

// adminDial asks the daemon for a TCP connection to addr on the mesh.
func adminDial(addr string) (net.Conn, error) {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, err
	}
	c, err := net.Dial("unix", node.AdminSocket(cfg.Node.StateDir))
	if err != nil {
		return nil, fmt.Errorf("no running node (is `zro join` running? zro ssh needs the same user, usually sudo): %w", err)
	}
	fmt.Fprintf(c, "POST /dial?addr=%s HTTP/1.1\r\nHost: zro\r\nContent-Length: 0\r\n\r\n", url.QueryEscape(addr))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		c.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer c.Close()
		var e struct{ Error string }
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return nil, errors.New(e.Error)
	}
	return bufferedConn{Conn: c, r: br}, nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func newSSHCmd() *cobra.Command {
	var forceTTY bool
	cmd := &cobra.Command{
		Use:   "ssh [user@]host [command...]",
		Short: "Open a shell on a peer over the mesh with its built-in SSH server",
		Long: `Open a shell on a peer over the mesh, or run a command there.

The peer must enable its SSH server (ssh.enabled, or zro join --ssh-user) and
grant you a local user in ssh.allow; the network policy must let this node
reach its SSH port. You prove who you are with this node's mesh identity, and
the peer's host key comes from the control plane: there are no keys to copy and
no host key to accept. Runs as the user that runs the node (usually sudo).`,
		Example:      "  sudo zro ssh ubuntu@web-1\n  sudo zro ssh web-1 -- uptime",
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			user, host, ok := strings.Cut(args[0], "@")
			if !ok {
				host, user = user, os.Getenv("SUDO_USER")
				if user == "" {
					user = os.Getenv("USER")
				}
			}
			var peer node.SSHPeer
			if err := localCall(http.MethodGet, "/ssh/peer?host="+url.QueryEscape(host), &peer); err != nil {
				return err
			}
			if peer.Port == 0 {
				return fmt.Errorf("%s has its SSH server off (ssh.enabled in its zro.yaml, or zro join --ssh-user)", peer.Hostname)
			}
			hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(peer.HostKey))
			if err != nil {
				return fmt.Errorf("%s has no valid SSH host key on the plane", peer.Hostname)
			}
			userKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(peer.User))
			if err != nil {
				return err
			}

			addr := net.JoinHostPort(peer.IP, strconv.Itoa(peer.Port))
			conn, err := adminDial(addr)
			if err != nil {
				return fmt.Errorf("reach %s: %w", addr, err)
			}
			sc, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
				User:            user,
				Auth:            []ssh.AuthMethod{ssh.PublicKeys(daemonSigner{userKey})},
				HostKeyCallback: ssh.FixedHostKey(hostKey),
			})
			if err != nil {
				conn.Close()
				return fmt.Errorf("ssh %s@%s: %w", user, peer.Hostname, err)
			}
			client := ssh.NewClient(sc, chans, reqs)
			defer client.Close()
			session, err := client.NewSession()
			if err != nil {
				return err
			}
			defer session.Close()
			session.Stdin, session.Stdout, session.Stderr = os.Stdin, os.Stdout, os.Stderr

			command := strings.Join(args[1:], " ")
			if fd := int(os.Stdin.Fd()); (command == "" || forceTTY) && isTerminal(fd) {
				w, h := termSize(fd)
				term := os.Getenv("TERM")
				if term == "" {
					term = "xterm-256color"
				}
				if err := session.RequestPty(term, h, w, ssh.TerminalModes{}); err != nil {
					return err
				}
				restore, err := makeRaw(fd)
				if err == nil {
					defer restore()
				}
				stop := watchResize(fd, func(w, h int) { _ = session.WindowChange(h, w) })
				defer stop()
			}
			if command == "" {
				err = session.Shell()
				if err == nil {
					err = session.Wait()
				}
			} else {
				err = session.Run(command)
			}
			var exit *ssh.ExitError
			if errors.As(err, &exit) {
				os.Exit(exit.ExitStatus())
			}
			return err
		},
	}
	cmd.Flags().BoolVarP(&forceTTY, "tty", "t", false, "Allocate a terminal for a command too")
	return cmd
}

// localCallBody is localCall with a request body.
func localCallBody(method, path string, body io.Reader, out any) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}
	sock := node.AdminSocket(cfg.Node.StateDir)
	c := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	req, _ := http.NewRequest(method, "http://zro"+path, body)
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("no running node at %s: %w", sock, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct{ Error string }
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return errors.New(e.Error)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
