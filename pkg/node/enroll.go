package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	v1 "github.com/cubetiqlabs/zro/api/proto/v1"
	"github.com/cubetiqlabs/zro/pkg/control/server"
	"github.com/cubetiqlabs/zro/pkg/core"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// permanentError marks an enrollment failure that retrying cannot fix (bad,
// expired or already used token; unknown network).
type permanentError struct{ error }

func (e permanentError) Unwrap() error { return e.error }

// enrollWithRetry enrolls, backing off 1s..30s on transient failures (plane
// down or restarting, network errors, 5xx) until ctx ends. Rejections by the
// plane are returned immediately.
func (d *Daemon) enrollWithRetry(ctx context.Context, endpoints []string, probes []core.LatencySample) (server.EnrollResponse, error) {
	backoff := time.Second
	for {
		resp, err := d.enroll(ctx, endpoints, probes)
		if err == nil {
			return resp, nil
		}
		var perm permanentError
		if errors.As(err, &perm) || ctx.Err() != nil {
			return resp, err
		}
		slog.Warn("Control plane unavailable, retrying enrollment", "error", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return resp, ctx.Err()
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

// enroll performs one enrollment attempt over gRPC when configured, else REST.
func (d *Daemon) enroll(ctx context.Context, endpoints []string, probes []core.LatencySample) (server.EnrollResponse, error) {
	var enrollResp server.EnrollResponse

	if d.grpcClient != nil {
		var protoProbes []*v1.LatencyProbe
		for _, p := range probes {
			protoProbes = append(protoProbes, &v1.LatencyProbe{
				PopCode:    p.PoPCode,
				RttNs:      p.RTT.Nanoseconds(),
				PacketLoss: p.PacketLoss,
			})
		}

		gResp, err := d.grpcClient.Enroll(ctx, &v1.EnrollRequest{
			Token:        d.cfg.EnrollmentToken,
			PublicKey:    d.keyPair.PublicKey,
			Hostname:     d.cfg.Hostname,
			NodeType:     "peer",
			Tags:         d.cfg.Tags,
			Endpoints:    endpoints,
			Probes:       protoProbes,
			AllowedPorts: d.allowedPorts,
			DefaultDeny:  &d.defaultDeny,
		})
		if err != nil {
			wrapped := fmt.Errorf("gRPC enrollment failed: %w", err)
			switch status.Code(err) {
			case codes.Unauthenticated, codes.PermissionDenied, codes.NotFound, codes.AlreadyExists, codes.InvalidArgument, codes.FailedPrecondition:
				return enrollResp, permanentError{wrapped}
			}
			return enrollResp, wrapped
		}

		nodeUUID, _ := uuid.Parse(gResp.NodeId)
		enrollResp = server.EnrollResponse{
			NodeID:      nodeUUID,
			NetworkID:   gResp.NetworkId,
			NodeToken:   gResp.NodeToken,
			ACLRules:    rulesFromProto(gResp.AclRules),
			IPv4CIDR:    gResp.Ipv4Cidr,
			IPv6CIDR:    gResp.Ipv6Cidr,
			OverlayIPv4: gResp.OverlayIpv4,
			OverlayIPv6: gResp.OverlayIpv6,
		}
		if gResp.PrimaryPop != nil {
			enrollResp.PrimaryPoP = core.EdgePoP{
				PoPCode:        gResp.PrimaryPop.PopCode,
				PublicEndpoint: gResp.PrimaryPop.PublicEndpoint,
				PublicKey:      gResp.PrimaryPop.PublicKey,
				Region:         gResp.PrimaryPop.Region,
			}
		}
		if gResp.SecondaryPop != nil {
			sec := core.EdgePoP{
				PoPCode:        gResp.SecondaryPop.PopCode,
				PublicEndpoint: gResp.SecondaryPop.PublicEndpoint,
				PublicKey:      gResp.SecondaryPop.PublicKey,
				Region:         gResp.SecondaryPop.Region,
			}
			enrollResp.SecondaryPoP = &sec
		}
		for _, p := range gResp.Peers {
			enrollResp.Peers = append(enrollResp.Peers, core.Node{
				Hostname:    p.Hostname,
				PublicKey:   p.PublicKey,
				OverlayIPv4: p.OverlayIpv4,
				OverlayIPv6: p.OverlayIpv6,
				Endpoints:   core.StringList(p.Endpoints),
				Tags:        core.StringList(p.Tags),
			})
		}
		return enrollResp, nil
	}

	enrollReq := server.EnrollRequest{
		Token:        d.cfg.EnrollmentToken,
		PublicKey:    d.keyPair.PublicKey,
		Hostname:     d.cfg.Hostname,
		NodeType:     core.NodeTypePeer,
		Tags:         core.StringList(d.cfg.Tags),
		Endpoints:    core.StringList(endpoints),
		AllowedPorts: core.StringList(d.allowedPorts),
		DefaultDeny:  &d.defaultDeny,
		Probes:       probes,
	}
	bodyBytes, err := json.Marshal(enrollReq)
	if err != nil {
		return enrollResp, permanentError{err}
	}
	req, err := http.NewRequestWithContext(ctx, "POST", d.cfg.PlaneEndpoint+"/api/v1/enroll", bytes.NewReader(bodyBytes))
	if err != nil {
		return enrollResp, permanentError{err}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return enrollResp, fmt.Errorf("enrollment request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		err := fmt.Errorf("enrollment rejected by control plane: status %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusRequestTimeout && resp.StatusCode != http.StatusTooManyRequests {
			return enrollResp, permanentError{err}
		}
		return enrollResp, err
	}
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return enrollResp, fmt.Errorf("failed to decode enrollment response: %w", err)
	}
	return enrollResp, nil
}
