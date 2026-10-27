package node

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cubetiqlabs/zro/pkg/core"
)

// AdminSocket is the node's local control socket inside its state directory.
// The directory is 0700 and the socket 0600, so only the daemon's own user (or
// root) can query or change the running node.
func AdminSocket(stateDir string) string { return filepath.Join(stateDir, "zro.sock") }

// PeerStatus is one peer as the node currently reaches it.
type PeerStatus struct {
	Hostname      string    `json:"hostname"`
	OverlayIPv4   string    `json:"overlay_ipv4"`
	Path          string    `json:"path"` // "direct" or "relay"
	Endpoint      string    `json:"endpoint,omitempty"`
	LastHandshake time.Time `json:"last_handshake,omitzero"`
	RxBytes       uint64    `json:"rx_bytes"`
	TxBytes       uint64    `json:"tx_bytes"`
}

// Status is the node's view of itself and the mesh.
type Status struct {
	Hostname     string       `json:"hostname"`
	NetworkID    string       `json:"network_id"`
	OverlayIPv4  string       `json:"overlay_ipv4"`
	OverlayIPv6  string       `json:"overlay_ipv6"`
	PoP          string       `json:"pop"`
	PoPEndpoint  string       `json:"pop_endpoint"`
	PoPHandshake time.Time    `json:"pop_handshake,omitzero"`
	Peers        []PeerStatus `json:"peers"`
}

// PingResult is the outcome of one mesh ping.
type PingResult struct {
	Target string  `json:"target"`
	IP     string  `json:"ip"`
	Path   string  `json:"path"`
	RTTMs  float64 `json:"rtt_ms"`
}

func (d *Daemon) serveAdmin(ctx context.Context) {
	defer d.wg.Done()
	if d.cfg.StateDir == "" {
		return
	}
	path := AdminSocket(d.cfg.StateDir)
	_ = os.Remove(path) // a socket left by a previous run
	ln, err := net.Listen("unix", path)
	if err != nil {
		slog.Warn("Local admin socket unavailable (zro status/ping will not work)", "path", path, "error", err)
		return
	}
	_ = os.Chmod(path, 0o600)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		writeAdminJSON(w, http.StatusOK, d.status())
	})
	mux.HandleFunc("POST /ping", func(w http.ResponseWriter, r *http.Request) {
		res, err := d.ping(r.Context(), r.URL.Query().Get("target"))
		if err != nil {
			writeAdminJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeAdminJSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("GET /policy", func(w http.ResponseWriter, r *http.Request) {
		writeAdminJSON(w, http.StatusOK, d.localPolicy())
	})
	mux.HandleFunc("POST /policy/allow", func(w http.ResponseWriter, r *http.Request) {
		d.adminPolicyChange(w, d.AllowService(r.URL.Query().Get("service")))
	})
	mux.HandleFunc("POST /policy/deny", func(w http.ResponseWriter, r *http.Request) {
		d.adminPolicyChange(w, d.DenyService(r.URL.Query().Get("service")))
	})
	mux.HandleFunc("GET /ssh/peer", func(w http.ResponseWriter, r *http.Request) {
		p, ok := d.peerByName(r.URL.Query().Get("host"))
		if !ok {
			writeAdminJSON(w, http.StatusNotFound, map[string]string{"error": "unknown peer: give a peer hostname or overlay IP"})
			return
		}
		writeAdminJSON(w, http.StatusOK, SSHPeer{Hostname: p.Hostname, IP: p.OverlayIPv4, Port: p.SSHPort, HostKey: p.SSHKey, User: d.sshPublicKey()})
	})
	mux.HandleFunc("POST /ssh/sign", func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if err != nil {
			writeAdminJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		sig, err := d.SignSSH(data)
		if err != nil {
			writeAdminJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeAdminJSON(w, http.StatusOK, sig)
	})
	mux.HandleFunc("POST /dial", d.adminDial)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	_ = srv.Serve(ln)
	_ = os.Remove(path)
}

// SSHPeer is what `zro ssh` needs to reach a peer's SSH server.
type SSHPeer struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`     // 0: the peer has SSH off
	HostKey  string `json:"host_key"` // pinned: no trust on first use
	User     string `json:"user_key"` // this node's key, which the client signs with
}

func (d *Daemon) peerByName(name string) (core.Node, bool) {
	if d.dnsDomain != "" {
		name = strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(name), "."), "."+d.dnsDomain)
	}
	if p, ok := d.peerByIP(name); ok {
		return p, true
	}
	d.peersMu.RLock()
	defer d.peersMu.RUnlock()
	for _, p := range d.peers {
		if p.Hostname == name {
			return p, true
		}
	}
	return core.Node{}, false
}

// adminDial opens a TCP connection to a peer's overlay address and hands the
// socket over to it, so local clients reach the mesh in netstack mode too.
// Only peers' overlay addresses can be dialed.
func (d *Daemon) adminDial(w http.ResponseWriter, r *http.Request) {
	ap, err := netip.ParseAddrPort(r.URL.Query().Get("addr"))
	if err != nil {
		writeAdminJSON(w, http.StatusBadRequest, map[string]string{"error": "addr must be ip:port"})
		return
	}
	if _, ok := d.peerByIP(ap.Addr().String()); !ok {
		writeAdminJSON(w, http.StatusForbidden, map[string]string{"error": "not a peer's overlay address"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	upstream, err := d.DialMesh(ctx, "tcp", ap.String())
	if err != nil {
		writeAdminJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	defer upstream.Close()
	c, buf, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer c.Close()
	_ = c.SetDeadline(time.Time{})
	_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, buf); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, upstream); done <- struct{}{} }()
	<-done
}

func (d *Daemon) adminPolicyChange(w http.ResponseWriter, err error) {
	if err != nil {
		writeAdminJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeAdminJSON(w, http.StatusOK, d.localPolicy())
}

func writeAdminJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (d *Daemon) status() Status {
	stats, _ := d.wgManager.Stats() // nil on a kernel device: paths still reported

	d.popMu.RLock()
	pop := d.primaryPoP
	d.popMu.RUnlock()
	st := Status{
		Hostname: d.cfg.Hostname, NetworkID: d.networkID,
		OverlayIPv4: d.overlayIPv4, OverlayIPv6: d.overlayIPv6,
		PoP: pop.PoPCode, PoPEndpoint: pop.PublicEndpoint,
		PoPHandshake: stats[pop.PublicKey].LastHandshake,
		Peers:        []PeerStatus{},
	}

	d.peersMu.RLock()
	for key, p := range d.peers {
		ps := PeerStatus{Hostname: p.Hostname, OverlayIPv4: p.OverlayIPv4, Path: "relay"}
		if d.direct.isDirect(key) {
			s := stats[key]
			ps.Path, ps.Endpoint, ps.LastHandshake, ps.RxBytes, ps.TxBytes = "direct", s.Endpoint, s.LastHandshake, s.RxBytes, s.TxBytes
		}
		st.Peers = append(st.Peers, ps)
	}
	d.peersMu.RUnlock()
	sort.Slice(st.Peers, func(i, j int) bool { return st.Peers[i].Hostname < st.Peers[j].Hostname })
	return st
}

// ping resolves target (a peer hostname or an overlay IP) and sends one echo.
func (d *Daemon) ping(ctx context.Context, target string) (PingResult, error) {
	res := PingResult{Target: target, Path: "relay"}
	ip, err := netip.ParseAddr(target)
	if p, ok := d.peerByName(target); ok {
		ip, err = netip.ParseAddr(p.OverlayIPv4)
		if d.direct.isDirect(p.PublicKey) {
			res.Path = "direct"
		}
	}
	if err != nil {
		return res, errors.New("unknown peer: give a peer hostname or overlay IP")
	}
	res.IP = ip.String()

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rtt, err := d.dev.Net.Ping(ctx, ip)
	if err != nil {
		return res, err
	}
	res.RTTMs = float64(rtt.Microseconds()) / 1000
	return res, nil
}
