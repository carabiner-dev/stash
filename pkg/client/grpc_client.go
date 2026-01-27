package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	stashv1 "github.com/carabiner-dev/stash/api/carabiner/stash/v1"
	"github.com/carabiner-dev/stash/pkg/client/config"
)

// GRPCClient is the Stash API client using gRPC.
type GRPCClient struct {
	conn   *grpc.ClientConn
	client stashv1.StashServiceClient
	token  string
}

// GRPCClientOptions contains options for creating a gRPC client.
type GRPCClientOptions struct {
	// Address is the server address (host:port).
	Address string

	// Token is the bearer token for authentication.
	Token string

	// Insecure disables TLS (for development only).
	Insecure bool

	// Timeout is the connection timeout.
	Timeout time.Duration
}

// NewGRPCClient creates a new gRPC client.
func NewGRPCClient(opts *GRPCClientOptions) (*GRPCClient, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}

	var dialOpts []grpc.DialOption

	if opts.Insecure {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, opts.Address, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("connecting to server: %w", err)
	}

	return &GRPCClient{
		conn:   conn,
		client: stashv1.NewStashServiceClient(conn),
		token:  opts.Token,
	}, nil
}

// NewGRPCClientFromConfig creates a gRPC client from configuration.
func NewGRPCClientFromConfig(cfg *config.Config) (*GRPCClient, error) {
	address, insecure := parseAddress(cfg.BaseURL)

	return NewGRPCClient(&GRPCClientOptions{
		Address:  address,
		Token:    cfg.Token,
		Insecure: insecure,
	})
}

// NewGRPCClientFromEnv creates a gRPC client from environment variables.
func NewGRPCClientFromEnv() (*GRPCClient, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, err
	}
	return NewGRPCClientFromConfig(cfg)
}

// Close closes the gRPC connection.
func (c *GRPCClient) Close() error {
	return c.conn.Close()
}

// ctxWithAuth adds authentication metadata to the context.
func (c *GRPCClient) ctxWithAuth(ctx context.Context) context.Context {
	if c.token == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.token)
}

// UploadAttestations uploads one or more attestations to the server.
// For gRPC, orgID comes from the bearer token in auth metadata, so orgID parameter is optional.
func (c *GRPCClient) UploadAttestations(ctx context.Context, orgID, namespace string, attestations [][]byte) ([]*UploadResult, error) {
	if len(attestations) == 0 {
		return nil, fmt.Errorf("no attestations provided")
	}
	if len(attestations) > 100 {
		return nil, fmt.Errorf("batch size exceeds maximum of 100")
	}

	// Validate orgID requirements (for consistency with REST client)
	if orgID == "" && c.token == "" {
		return nil, fmt.Errorf("orgID required for unauthenticated requests")
	}

	resp, err := c.client.UploadAttestations(c.ctxWithAuth(ctx), &stashv1.UploadAttestationsRequest{
		Namespace:    namespace,
		Attestations: attestations,
	})
	if err != nil {
		return nil, err
	}

	results := make([]*UploadResult, len(resp.Results))
	for i, r := range resp.Results {
		results[i] = &UploadResult{
			AttestationID: r.AttestationId,
			ContentHash:   r.ContentHash,
			Existed:       r.Stored && r.AttestationId != "",
			Error:         r.Error,
		}
	}

	return results, nil
}

// GetAttestation retrieves an attestation by ID or hash.
// For gRPC, orgID comes from the bearer token in auth metadata, so orgID parameter is optional.
func (c *GRPCClient) GetAttestation(ctx context.Context, orgID, namespace, id string) (*Attestation, []byte, []byte, error) {
	// Validate orgID requirements (for consistency with REST client)
	if orgID == "" && c.token == "" {
		return nil, nil, nil, fmt.Errorf("orgID required for unauthenticated requests")
	}

	resp, err := c.client.GetAttestation(c.ctxWithAuth(ctx), &stashv1.GetAttestationRequest{
		Namespace:  namespace,
		Identifier: &stashv1.GetAttestationRequest_AttestationId{AttestationId: id},
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return protoToAttestation(resp.Attestation), resp.RawAttestation, resp.RawPredicate, nil
}

// GetAttestationRaw retrieves only the raw attestation JSON.
func (c *GRPCClient) GetAttestationRaw(ctx context.Context, orgID, namespace, id string) ([]byte, error) {
	resp, err := c.client.GetAttestation(c.ctxWithAuth(ctx), &stashv1.GetAttestationRequest{
		Namespace:  namespace,
		Identifier: &stashv1.GetAttestationRequest_AttestationId{AttestationId: id},
		RawOnly:    true,
	})
	if err != nil {
		return nil, err
	}
	return resp.RawAttestation, nil
}

// GetAttestationPredicate retrieves only the predicate JSON.
func (c *GRPCClient) GetAttestationPredicate(ctx context.Context, orgID, namespace, id string) ([]byte, error) {
	resp, err := c.client.GetAttestation(c.ctxWithAuth(ctx), &stashv1.GetAttestationRequest{
		Namespace:  namespace,
		Identifier: &stashv1.GetAttestationRequest_AttestationId{AttestationId: id},
		PredicateOnly: true,
	})
	if err != nil {
		return nil, err
	}
	return resp.RawPredicate, nil
}

// GetAttestationByHash retrieves an attestation by content hash.
func (c *GRPCClient) GetAttestationByHash(ctx context.Context, orgID, namespace, hash string) (*Attestation, []byte, []byte, error) {
	resp, err := c.client.GetAttestation(c.ctxWithAuth(ctx), &stashv1.GetAttestationRequest{
		Namespace:  namespace,
		Identifier: &stashv1.GetAttestationRequest_ContentHash{ContentHash: hash},
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return protoToAttestation(resp.Attestation), resp.RawAttestation, resp.RawPredicate, nil
}

// GetAttestationByPredicateHash retrieves an attestation by predicate hash.
func (c *GRPCClient) GetAttestationByPredicateHash(ctx context.Context, orgID, namespace, hash string) (*Attestation, []byte, []byte, error) {
	resp, err := c.client.GetAttestation(c.ctxWithAuth(ctx), &stashv1.GetAttestationRequest{
		Namespace:  namespace,
		Identifier: &stashv1.GetAttestationRequest_PredicateHash{PredicateHash: hash},
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return protoToAttestation(resp.Attestation), resp.RawAttestation, resp.RawPredicate, nil
}

// ListAttestations lists attestations with optional filters and pagination.
func (c *GRPCClient) ListAttestations(ctx context.Context, orgID, namespace string, filters *Filters, cursor *Cursor) (*AttestationList, error) {
	req := &stashv1.ListAttestationsRequest{
		Namespace: namespace,
	}

	if filters != nil {
		req.Filters = &stashv1.Filters{
			PredicateType:    filters.PredicateType,
			SubjectName:      filters.SubjectName,
			SubjectDigest:    filters.SubjectDigest,
			SubjectUri:       filters.SubjectURI,
			SubjectNameRegex: filters.SubjectNameRegex,
			SubjectUriRegex:  filters.SubjectURIRegex,
			SignerIdentity:   filters.SignerIdentity,
			SignedOnly:       filters.SignedOnly,
			ValidatedOnly:    filters.ValidatedOnly,
		}
	}

	if cursor != nil {
		req.Cursor = &stashv1.Cursor{
			Limit:  int32(cursor.Limit),
			Offset: cursor.Token,
		}
	}

	resp, err := c.client.ListAttestations(c.ctxWithAuth(ctx), req)
	if err != nil {
		return nil, err
	}

	result := &AttestationList{
		Attestations: make([]*Attestation, len(resp.Attestations)),
	}

	for i, att := range resp.Attestations {
		result.Attestations[i] = protoToAttestation(att)
	}

	if resp.NextCursor != nil {
		result.NextCursor = resp.NextCursor.Offset
	}

	return result, nil
}

// DeleteAttestation deletes an attestation by ID or hash.
func (c *GRPCClient) DeleteAttestation(ctx context.Context, orgID, namespace, id string) error {
	_, err := c.client.DeleteAttestation(c.ctxWithAuth(ctx), &stashv1.DeleteAttestationRequest{
		Namespace:  namespace,
		Identifier: &stashv1.DeleteAttestationRequest_AttestationId{AttestationId: id},
	})
	return err
}

// UpdateAttestation updates an attestation (currently not implemented).
func (c *GRPCClient) UpdateAttestation(ctx context.Context, orgID, namespace, id string, updates map[string]interface{}) error {
	_, err := c.client.UpdateAttestation(c.ctxWithAuth(ctx), &stashv1.UpdateAttestationRequest{
		Namespace:     namespace,
		AttestationId: id,
	})
	return err
}

// UploadPublicKey uploads a public key.
func (c *GRPCClient) UploadPublicKey(ctx context.Context, keyData []byte) (string, error) {
	resp, err := c.client.UploadPublicKey(c.ctxWithAuth(ctx), &stashv1.UploadPublicKeyRequest{
		KeyData: keyData,
	})
	if err != nil {
		return "", err
	}
	return resp.KeyId, nil
}

// ListPublicKeys lists all public keys.
func (c *GRPCClient) ListPublicKeys(ctx context.Context) ([]*PublicKey, error) {
	resp, err := c.client.ListPublicKeys(c.ctxWithAuth(ctx), &stashv1.ListPublicKeysRequest{})
	if err != nil {
		return nil, err
	}

	keys := make([]*PublicKey, len(resp.Keys))
	for i, k := range resp.Keys {
		keys[i] = &PublicKey{
			KeyID:     k.KeyId,
			Algorithm: k.Algorithm,
			CreatedAt: k.CreatedAt.AsTime(),
		}
	}

	return keys, nil
}

// GetPublicKey retrieves a public key by ID (not in proto, uses list and filter).
func (c *GRPCClient) GetPublicKey(ctx context.Context, keyID string) (*PublicKey, error) {
	keys, err := c.ListPublicKeys(ctx)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if k.KeyID == keyID {
			return k, nil
		}
	}
	return nil, fmt.Errorf("public key not found: %s", keyID)
}

// DeletePublicKey deletes a public key.
func (c *GRPCClient) DeletePublicKey(ctx context.Context, keyID string) error {
	_, err := c.client.DeletePublicKey(c.ctxWithAuth(ctx), &stashv1.DeletePublicKeyRequest{
		KeyId: keyID,
	})
	return err
}

// CreateNamespace creates a new namespace (not implemented in gRPC yet).
func (c *GRPCClient) CreateNamespace(ctx context.Context, orgID, name string) (*Namespace, error) {
	return nil, fmt.Errorf("namespace operations not supported via gRPC (proto definitions not yet updated)")
}

// GetNamespace retrieves a namespace (not implemented in gRPC yet).
func (c *GRPCClient) GetNamespace(ctx context.Context, orgID, name string) (*Namespace, error) {
	return nil, fmt.Errorf("namespace operations not supported via gRPC (proto definitions not yet updated)")
}

// ListNamespaces lists namespaces (not implemented in gRPC yet).
func (c *GRPCClient) ListNamespaces(ctx context.Context, orgID string) ([]*Namespace, error) {
	return nil, fmt.Errorf("namespace operations not supported via gRPC (proto definitions not yet updated)")
}

// DeleteNamespace deletes a namespace (not implemented in gRPC yet).
func (c *GRPCClient) DeleteNamespace(ctx context.Context, orgID, name string) error {
	return fmt.Errorf("namespace operations not supported via gRPC (proto definitions not yet updated)")
}

// HealthCheck checks server health.
func (c *GRPCClient) HealthCheck(ctx context.Context) (string, map[string]string, error) {
	resp, err := c.client.HealthCheck(c.ctxWithAuth(ctx), &stashv1.HealthCheckRequest{})
	if err != nil {
		return "", nil, err
	}
	return resp.Status, resp.Components, nil
}
