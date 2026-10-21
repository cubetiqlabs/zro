// Package enroll holds the enrollment-token checks shared by the REST and gRPC
// control-plane servers, so both transports enforce identical rules.
package enroll

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/cubis/zro/pkg/core"
	"github.com/cubis/zro/pkg/crypto"
)

// Typed failures; transports map them to HTTP/gRPC status codes.
var (
	ErrUnauthenticated = errors.New("enrollment rejected")
	ErrForbidden       = errors.New("enrollment forbidden")
	ErrConflict        = errors.New("enrollment conflict")
)

// Request is the transport-independent part of an enrollment call.
type Request struct {
	Token     string
	PublicKey string
	Hostname  string
	NodeType  core.NodeType
}

// Grant is the verified outcome of an enrollment request.
type Grant struct {
	NetworkID string
	Hostname  string
	NodeType  core.NodeType
}

// Authorize verifies the token, checks that the request matches the claims the
// token was minted with, and redeems the token's nonce so it can only be used
// by one key. The node type comes from the token, never from the request.
func Authorize(ctx context.Context, secretKey string, repo core.EnrollmentRepository, req Request) (*Grant, error) {
	if err := crypto.ValidatePublicKey(req.PublicKey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	claims, err := crypto.VerifyEnrollmentToken(secretKey, req.Token, req.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}

	hostname := req.Hostname
	switch {
	case hostname == "":
		hostname = claims.Hostname
	case claims.Hostname != "" && subtle.ConstantTimeCompare([]byte(hostname), []byte(claims.Hostname)) != 1:
		return nil, fmt.Errorf("%w: hostname does not match token", ErrForbidden)
	}

	nodeType := core.NodeType(claims.NodeType)
	if nodeType == "" {
		nodeType = core.NodeTypePeer
	}
	if req.NodeType != "" && req.NodeType != nodeType {
		return nil, fmt.Errorf("%w: token does not permit node type %q", ErrForbidden, req.NodeType)
	}

	if err := repo.Redeem(ctx, claims.Nonce, req.PublicKey, claims.ExpiresAt); err != nil {
		if errors.Is(err, core.ErrTokenReused) {
			return nil, fmt.Errorf("%w: %v", ErrConflict, err)
		}
		return nil, err
	}
	return &Grant{NetworkID: claims.NetworkID, Hostname: hostname, NodeType: nodeType}, nil
}
