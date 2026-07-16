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

// testOrgID is the organization these tests address. ValidateOrgID requires a
// DNS hostname, so it cannot be an arbitrary word.
const testOrgID = "acme.example.com"

// captureServer records the requests it receives so tests can assert on the
// fields the client actually sent over the wire.
type captureServer struct {
	stashv1.UnimplementedStashServiceServer
	deleteReq  *stashv1.DeleteAttestationRequest
	updateReq  *stashv1.UpdateAttestationRequest
	uploadReq  *stashv1.UploadAttestationsRequest
	uploadResp *stashv1.UploadAttestationsResponse

	pushPoliciesReq  *stashv1.PushPoliciesRequest
	pushPoliciesResp *stashv1.PushPoliciesResponse
	appendPolicyReq  *stashv1.AppendPolicyRequest
	appendPolicyResp *stashv1.AppendPolicyResponse
	getPolicyReq     *stashv1.GetPolicyRequest
	getPolicyResp    *stashv1.GetPolicyResponse
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

func (s *captureServer) PushPolicies(_ context.Context, req *stashv1.PushPoliciesRequest) (*stashv1.PushPoliciesResponse, error) {
	s.pushPoliciesReq = req
	if s.pushPoliciesResp != nil {
		return s.pushPoliciesResp, nil
	}
	return &stashv1.PushPoliciesResponse{}, nil
}

func (s *captureServer) AppendPolicy(_ context.Context, req *stashv1.AppendPolicyRequest) (*stashv1.AppendPolicyResponse, error) {
	s.appendPolicyReq = req
	if s.appendPolicyResp != nil {
		return s.appendPolicyResp, nil
	}
	return &stashv1.AppendPolicyResponse{}, nil
}

func (s *captureServer) GetPolicy(_ context.Context, req *stashv1.GetPolicyRequest) (*stashv1.GetPolicyResponse, error) {
	s.getPolicyReq = req
	if s.getPolicyResp != nil {
		return s.getPolicyResp, nil
	}
	return &stashv1.GetPolicyResponse{}, nil
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

	if err := c.DeleteAttestation(context.Background(), testOrgID, "ns", "att-123"); err != nil {
		t.Fatalf("DeleteAttestation: %v", err)
	}

	if got := capture.deleteReq.GetOrgId(); got != testOrgID {
		t.Errorf("org_id: got %q, want %q", got, testOrgID)
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
	if err := c.DeleteAttestation(context.Background(), testOrgID, "", hash); err != nil {
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

	results, err := c.UploadAttestations(context.Background(), testOrgID, "", [][]byte{[]byte("{}"), []byte("{}")})
	if err != nil {
		t.Fatalf("UploadAttestations: %v", err)
	}

	if got := capture.uploadReq.GetOrgId(); got != testOrgID {
		t.Errorf("org_id: got %q, want %q", got, testOrgID)
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

	if err := c.UpdateAttestation(context.Background(), testOrgID, "ns", "att-123", nil); err != nil {
		t.Fatalf("UpdateAttestation: %v", err)
	}

	if got := capture.updateReq.GetOrgId(); got != testOrgID {
		t.Errorf("org_id: got %q, want %q", got, testOrgID)
	}
}

func TestGRPCPushPoliciesSendsOrgIDAndResults(t *testing.T) {
	c, capture := newBufconnClient(t)
	capture.pushPoliciesResp = &stashv1.PushPoliciesResponse{
		Results: []*stashv1.PolicyResult{
			{LineageId: "lin-a", Version: 0, DocumentKind: "policy", ContentHash: "aaa"},
			{LineageId: "lin-b", ContentHash: "bbb", Existed: true},
			{LineageId: "lin-c", Error: "rejected"},
		},
	}

	results, err := c.PushPolicies(context.Background(), testOrgID, "ns", [][]byte{[]byte("{}"), []byte("{}"), []byte("{}")})
	if err != nil {
		t.Fatalf("PushPolicies: %v", err)
	}

	if got := capture.pushPoliciesReq.GetOrgId(); got != testOrgID {
		t.Errorf("org_id: got %q, want %q", got, testOrgID)
	}
	if got := capture.pushPoliciesReq.GetNamespace(); got != "ns" {
		t.Errorf("namespace: got %q, want %q", got, "ns")
	}
	if got := len(capture.pushPoliciesReq.GetPolicies()); got != 3 {
		t.Errorf("policies sent: got %d, want 3", got)
	}

	// Per-document results are returned in order.
	if len(results) != 3 {
		t.Fatalf("results: got %d, want 3", len(results))
	}
	if results[0].LineageID != "lin-a" || results[0].DocumentKind != "policy" {
		t.Errorf("result[0]: got %+v", results[0])
	}
	if !results[1].Existed {
		t.Error("result[1] should report Existed")
	}
	if results[2].Error != "rejected" {
		t.Errorf("result[2] error: got %q, want %q", results[2].Error, "rejected")
	}
}

func TestGRPCAppendPolicySendsOrgID(t *testing.T) {
	c, capture := newBufconnClient(t)
	capture.appendPolicyResp = &stashv1.AppendPolicyResponse{
		Result: &stashv1.PolicyResult{LineageId: "lin-a", Version: 3},
	}

	result, err := c.AppendPolicy(context.Background(), testOrgID, "ns", "lin-a", []byte("{}"))
	if err != nil {
		t.Fatalf("AppendPolicy: %v", err)
	}

	if got := capture.appendPolicyReq.GetOrgId(); got != testOrgID {
		t.Errorf("org_id: got %q, want %q", got, testOrgID)
	}
	if got := capture.appendPolicyReq.GetLineageId(); got != "lin-a" {
		t.Errorf("lineage_id: got %q, want %q", got, "lin-a")
	}
	if result.Version != 3 {
		t.Errorf("result version: got %d, want 3", result.Version)
	}
}

func TestGRPCGetPolicyPassesVersion(t *testing.T) {
	// A nil version reads latest and must not set the field on the wire.
	t.Run("latest", func(t *testing.T) {
		c, capture := newBufconnClient(t)
		capture.getPolicyResp = &stashv1.GetPolicyResponse{
			Policy: &stashv1.Policy{LineageId: "lin-a", Version: 7},
			Raw:    []byte("{}"),
		}

		pol, raw, err := c.GetPolicy(context.Background(), testOrgID, "ns", "lin-a", nil)
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		if got := capture.getPolicyReq.GetOrgId(); got != testOrgID {
			t.Errorf("org_id: got %q, want %q", got, testOrgID)
		}
		if capture.getPolicyReq.Version != nil {
			t.Errorf("version should be nil for latest, got %d", capture.getPolicyReq.GetVersion())
		}
		if pol.Version != 7 {
			t.Errorf("policy version: got %d, want 7", pol.Version)
		}
		if string(raw) != "{}" {
			t.Errorf("raw: got %q, want %q", string(raw), "{}")
		}
	})

	// An explicit 0 is version 0, distinct from "latest".
	t.Run("explicit zero", func(t *testing.T) {
		c, capture := newBufconnClient(t)
		capture.getPolicyResp = &stashv1.GetPolicyResponse{Policy: &stashv1.Policy{}}

		v := int64(0)
		if _, _, err := c.GetPolicy(context.Background(), testOrgID, "ns", "lin-a", &v); err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		if capture.getPolicyReq.Version == nil {
			t.Fatal("version should be set for explicit 0")
		}
		if got := capture.getPolicyReq.GetVersion(); got != 0 {
			t.Errorf("version: got %d, want 0", got)
		}
	})

	t.Run("explicit value", func(t *testing.T) {
		c, capture := newBufconnClient(t)
		capture.getPolicyResp = &stashv1.GetPolicyResponse{Policy: &stashv1.Policy{}}

		v := int64(5)
		if _, _, err := c.GetPolicy(context.Background(), testOrgID, "ns", "lin-a", &v); err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		if capture.getPolicyReq.Version == nil {
			t.Fatal("version should be set for explicit value")
		}
		if got := capture.getPolicyReq.GetVersion(); got != 5 {
			t.Errorf("version: got %d, want 5", got)
		}
	})
}
