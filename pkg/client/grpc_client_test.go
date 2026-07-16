// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	stashv1 "github.com/carabiner-dev/stash/api/carabiner/stash/v1"
)

// captureServer records the requests it receives so tests can assert on the
// fields the client actually sent over the wire.
type captureServer struct {
	stashv1.UnimplementedStashServiceServer
	deleteReq  *stashv1.DeleteAttestationRequest
	updateReq  *stashv1.UpdateAttestationRequest
	uploadReq  *stashv1.UploadAttestationsRequest
	uploadResp *stashv1.UploadAttestationsResponse
}

func (s *captureServer) UploadAttestations(_ context.Context, req *stashv1.UploadAttestationsRequest) (*stashv1.UploadAttestationsResponse, error) {
	s.uploadReq = req
	return s.uploadResp, nil
}

func (s *captureServer) DeleteAttestation(_ context.Context, req *stashv1.DeleteAttestationRequest) (*stashv1.DeleteAttestationResponse, error) {
	s.deleteReq = req
	return &stashv1.DeleteAttestationResponse{}, nil
}

func (s *captureServer) UpdateAttestation(_ context.Context, req *stashv1.UpdateAttestationRequest) (*stashv1.UpdateAttestationResponse, error) {
	s.updateReq = req
	return &stashv1.UpdateAttestationResponse{}, nil
}

// newBufconnClient starts an in-process gRPC server and returns a GRPCClient
// connected to it.
func newBufconnClient(t *testing.T) (*GRPCClient, *captureServer) {
	t.Helper()

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	capture := &captureServer{}
	stashv1.RegisterStashServiceServer(srv, capture)
	go srv.Serve(lis) //nolint:errcheck

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dialing bufconn: %v", err)
	}

	t.Cleanup(func() {
		conn.Close() //nolint:errcheck,gosec
		srv.Stop()
	})

	return &GRPCClient{conn: conn, client: stashv1.NewStashServiceClient(conn)}, capture
}

func TestGRPCDeleteAttestationSendsOrgID(t *testing.T) {
	c, capture := newBufconnClient(t)

	if err := c.DeleteAttestation(context.Background(), "acme.example.com", "ns", "att-123"); err != nil {
		t.Fatalf("DeleteAttestation: %v", err)
	}

	if got := capture.deleteReq.GetOrgId(); got != "acme.example.com" {
		t.Errorf("org_id: got %q, want %q", got, "acme.example.com")
	}
	if got := capture.deleteReq.GetNamespace(); got != "ns" {
		t.Errorf("namespace: got %q, want %q", got, "ns")
	}
	if got := capture.deleteReq.GetAttestationId(); got != "att-123" {
		t.Errorf("attestation_id: got %q, want %q", got, "att-123")
	}
}

func TestGRPCDeleteAttestationByHash(t *testing.T) {
	c, capture := newBufconnClient(t)

	hash := "sha256:a1b2c3d4"
	if err := c.DeleteAttestation(context.Background(), "acme.example.com", "", hash); err != nil {
		t.Fatalf("DeleteAttestation: %v", err)
	}

	if got := capture.deleteReq.GetContentHash(); got != hash {
		t.Errorf("content_hash: got %q, want %q", got, hash)
	}
	if got := capture.deleteReq.GetAttestationId(); got != "" {
		t.Errorf("attestation_id should be empty when deleting by hash, got %q", got)
	}
}

func TestGRPCDeleteAttestationRequiresOrg(t *testing.T) {
	c, _ := newBufconnClient(t)

	if err := c.DeleteAttestation(context.Background(), "", "", "att-123"); err == nil {
		t.Fatal("expected an error when no org ID is available")
	}
}

func TestGRPCUploadAttestationsExisted(t *testing.T) {
	c, capture := newBufconnClient(t)
	capture.uploadResp = &stashv1.UploadAttestationsResponse{
		Results: []*stashv1.AttestationResult{
			{AttestationId: "att-new", ContentHash: "aaa", Stored: true},
			{AttestationId: "att-dup", ContentHash: "bbb", Stored: true, Existed: true},
		},
	}

	results, err := c.UploadAttestations(context.Background(), "acme.example.com", "", [][]byte{[]byte("{}"), []byte("{}")})
	if err != nil {
		t.Fatalf("UploadAttestations: %v", err)
	}

	if got := capture.uploadReq.GetOrgId(); got != "acme.example.com" {
		t.Errorf("org_id: got %q, want %q", got, "acme.example.com")
	}
	if results[0].Existed {
		t.Error("freshly stored attestation reported as already existing")
	}
	if !results[1].Existed {
		t.Error("duplicate attestation not reported as already existing")
	}
}

func TestGRPCUpdateAttestationSendsOrgID(t *testing.T) {
	c, capture := newBufconnClient(t)

	if err := c.UpdateAttestation(context.Background(), "acme.example.com", "ns", "att-123", nil); err != nil {
		t.Fatalf("UpdateAttestation: %v", err)
	}

	if got := capture.updateReq.GetOrgId(); got != "acme.example.com" {
		t.Errorf("org_id: got %q, want %q", got, "acme.example.com")
	}
}
