package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	v1 "github.com/cubetiqlabs/zro/api/proto/v1"
	"github.com/cubetiqlabs/zro/pkg/config"
	controlgrpc "github.com/cubetiqlabs/zro/pkg/control/grpc"
	"github.com/cubetiqlabs/zro/pkg/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func writeSelfSigned(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile = filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	return certFile, keyFile
}

func TestGRPCTransportSecurity(t *testing.T) {
	db, err := store.NewDB("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}

	// Plaintext must be an explicit opt-in.
	noTLS := NewServer(&config.ControlPlaneConfig{SecretKey: "s"}, db)
	if _, err := noTLS.grpcTransportCredentials(); err == nil {
		t.Fatal("gRPC without TLS and without grpc_insecure must be refused")
	}

	certFile, keyFile := writeSelfSigned(t, t.TempDir())
	srv := NewServer(&config.ControlPlaneConfig{SecretKey: "s", GRPCTLSCert: certFile, GRPCTLSKey: keyFile}, db)
	creds, err := srv.grpcTransportCredentials()
	if err != nil {
		t.Fatal(err)
	}
	g := srv.NewGRPCServer(grpc.Creds(creds))
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = g.Serve(lis) }()
	defer g.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// TLS client pinned to the server cert reaches the (authenticated) service.
	tlsClient, err := controlgrpc.Dial(controlgrpc.DialOptions{Endpoint: lis.Addr().String(), CAFile: certFile})
	if err != nil {
		t.Fatal(err)
	}
	defer tlsClient.Close()
	_, err = tlsClient.ReportProbes(ctx, &v1.ProbeReportRequest{PopCode: "KH"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated over TLS without credentials, got %v", err)
	}

	// A TLS client that does not trust the cert, and a plaintext client, both fail to connect.
	untrusted, _ := controlgrpc.Dial(controlgrpc.DialOptions{Endpoint: lis.Addr().String()})
	defer untrusted.Close()
	if _, err := untrusted.ReportProbes(ctx, &v1.ProbeReportRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("untrusted TLS client should fail with Unavailable, got %v", err)
	}
	plain, _ := controlgrpc.Dial(controlgrpc.DialOptions{Endpoint: lis.Addr().String(), Insecure: true})
	defer plain.Close()
	if _, err := plain.ReportProbes(ctx, &v1.ProbeReportRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("plaintext client should fail with Unavailable, got %v", err)
	}
}
