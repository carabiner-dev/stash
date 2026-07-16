package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
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
	config *config.Config // For dynamic token retrieval
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

	conn, err := grpc.NewClient(opts.Address, dialOpts...)
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
	address, insecureConn := parseAddress(cfg.BaseURL)

	client, err := NewGRPCClient(&GRPCClientOptions{
		Address:  address,
		Token:    "", // Token will be fetched dynamically from config
		Insecure: insecureConn,
	})
	if err != nil {
		return nil, err
	}

	// Store config for dynamic token retrieval
	client.config = cfg
	return client, nil
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

// resolveOrgID resolves the organization ID, deriving from token if not provided.
// For single-org tokens, the org can be automatically derived.
// For multi-org tokens, the user must explicitly provide the org ID.
func (c *GRPCClient) resolveOrgID(ctx context.Context, orgID string) (string, error) {
	// If orgID provided, use it
	if orgID != "" {
		return orgID, nil
	}

	// Try to derive from token if config available
	if c.config != nil {
		derivedOrg, err := c.config.DeriveOrgFromToken(ctx)
		if err != nil {
			return "", fmt.Errorf("deriving org from token: %w", err)
		}
		if derivedOrg != "" {
			return derivedOrg, nil
		}
		// derivedOrg is empty means multiple orgs or no orgs
		return "", fmt.Errorf("org ID required: token has access to multiple organizations, please specify --org")
	}

	return "", fmt.Errorf("org ID required")
}

// ctxWithAuth adds authentication metadata to the context.
func (c *GRPCClient) ctxWithAuth(ctx context.Context) (context.Context, error) {
	var token string

	// Try to get token from config's credentials manager first
	if c.config != nil {
		t, err := c.config.GetToken(ctx)
		if err != nil {
			return ctx, err
		}
		token = t
	} else if c.token != "" {
		// Fall back to static token if no config
		token = c.token
	}

	if token == "" {
		return ctx, nil
	}

	// Add authorization header with token (which includes namespace claims)
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)

	return ctx, nil
}

// UploadAttestations uploads one or more attestations to the server.
func (c *GRPCClient) UploadAttestations(ctx context.Context, orgID, namespace string, attestations [][]byte) ([]*UploadResult, error) {
	if len(attestations) == 0 {
		return nil, fmt.Errorf("no attestations provided")
	}
	if len(attestations) > 100 {
		return nil, fmt.Errorf("batch size exceeds maximum of 100")
	}

	// Resolve orgID - derive from token if not provided
	resolvedOrgID, err := c.resolveOrgID(ctx, orgID)
	if err != nil {
		return nil, err
	}

	// Validate orgID format
	if err := ValidateOrgID(resolvedOrgID); err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	authCtx, err := c.ctxWithAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting auth context: %w", err)
	}

	resp, err := c.client.UploadAttestations(authCtx, &stashv1.UploadAttestationsRequest{
		Namespace:    namespace,
		Attestations: attestations,
		OrgId:        resolvedOrgID,
	})
	if err != nil {
		return nil, err
	}

	results := make([]*UploadResult, len(resp.GetResults()))
	for i, r := range resp.GetResults() {
		results[i] = &UploadResult{
			AttestationID: r.GetAttestationId(),
			ContentHash:   r.GetContentHash(),
			Existed:       r.GetExisted(),
			Error:         r.GetError(),
		}
	}

	return results, nil
}

// GetAttestation retrieves an attestation by ID or hash.
func (c *GRPCClient) GetAttestation(ctx context.Context, orgID, namespace, id string) (att *Attestation, raw, predicate []byte, err error) {
	// Resolve orgID - derive from token if not provided
	resolvedOrgID, err := c.resolveOrgID(ctx, orgID)
	if err != nil {
		return nil, nil, nil, err
	}

	// Validate orgID format
	if err := ValidateOrgID(resolvedOrgID); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid org ID: %w", err)
	}

	authCtx, err := c.ctxWithAuth(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("getting auth context: %w", err)
	}

	resp, err := c.client.GetAttestation(authCtx, &stashv1.GetAttestationRequest{
		Namespace:  namespace,
		Identifier: &stashv1.GetAttestationRequest_AttestationId{AttestationId: id},
		OrgId:      resolvedOrgID,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return protoToAttestation(resp.GetAttestation()), resp.GetRawAttestation(), resp.GetRawPredicate(), nil
}

// GetAttestationRaw retrieves only the raw attestation JSON.
func (c *GRPCClient) GetAttestationRaw(ctx context.Context, orgID, namespace, id string) ([]byte, error) {
	// Resolve orgID - derive from token if not provided
	resolvedOrgID, err := c.resolveOrgID(ctx, orgID)
	if err != nil {
		return nil, err
	}

	// Validate orgID format
	if err := ValidateOrgID(resolvedOrgID); err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	authCtx, err := c.ctxWithAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting auth context: %w", err)
	}

	resp, err := c.client.GetAttestation(authCtx, &stashv1.GetAttestationRequest{
		Namespace:  namespace,
		Identifier: &stashv1.GetAttestationRequest_AttestationId{AttestationId: id},
		RawOnly:    true,
		OrgId:      resolvedOrgID,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetRawAttestation(), nil
}

// GetAttestationPredicate retrieves only the predicate JSON.
func (c *GRPCClient) GetAttestationPredicate(ctx context.Context, orgID, namespace, id string) ([]byte, error) {
	authCtx, err := c.ctxWithAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting auth context: %w", err)
	}

	resp, err := c.client.GetAttestation(authCtx, &stashv1.GetAttestationRequest{
		Namespace:     namespace,
		Identifier:    &stashv1.GetAttestationRequest_AttestationId{AttestationId: id},
		PredicateOnly: true,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetRawPredicate(), nil
}

// GetAttestationByHash retrieves an attestation by content hash.
func (c *GRPCClient) GetAttestationByHash(ctx context.Context, orgID, namespace, hash string) (att *Attestation, raw, predicate []byte, err error) {
	authCtx, err := c.ctxWithAuth(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("getting auth context: %w", err)
	}

	resp, err := c.client.GetAttestation(authCtx, &stashv1.GetAttestationRequest{
		Namespace:  namespace,
		Identifier: &stashv1.GetAttestationRequest_ContentHash{ContentHash: hash},
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return protoToAttestation(resp.GetAttestation()), resp.GetRawAttestation(), resp.GetRawPredicate(), nil
}

// GetAttestationByPredicateHash retrieves an attestation by predicate hash.
func (c *GRPCClient) GetAttestationByPredicateHash(ctx context.Context, orgID, namespace, hash string) (att *Attestation, raw, predicate []byte, err error) {
	authCtx, err := c.ctxWithAuth(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("getting auth context: %w", err)
	}

	resp, err := c.client.GetAttestation(authCtx, &stashv1.GetAttestationRequest{
		Namespace:  namespace,
		Identifier: &stashv1.GetAttestationRequest_PredicateHash{PredicateHash: hash},
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return protoToAttestation(resp.GetAttestation()), resp.GetRawAttestation(), resp.GetRawPredicate(), nil
}

// ListAttestations lists attestations with optional filters and pagination.
func (c *GRPCClient) ListAttestations(ctx context.Context, orgID, namespace string, filters *Filters, cursor *Cursor) (*AttestationList, error) {
	// Resolve orgID - derive from token if not provided
	resolvedOrgID, err := c.resolveOrgID(ctx, orgID)
	if err != nil {
		return nil, err
	}

	// Validate orgID format
	if err := ValidateOrgID(resolvedOrgID); err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	req := &stashv1.ListAttestationsRequest{
		Namespace: namespace,
		OrgId:     resolvedOrgID,
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
		// Clamp to the documented maximum (1000) to avoid overflowing int32
		limit := cursor.Limit
		if limit < 0 {
			limit = 0
		}
		if limit > 1000 {
			limit = 1000
		}
		req.Cursor = &stashv1.Cursor{
			Limit:  int32(limit),
			Offset: cursor.Token,
		}
	}

	authCtx, err := c.ctxWithAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting auth context: %w", err)
	}

	resp, err := c.client.ListAttestations(authCtx, req)
	if err != nil {
		return nil, err
	}

	result := &AttestationList{
		Attestations: make([]*Attestation, len(resp.GetAttestations())),
	}

	for i, att := range resp.GetAttestations() {
		result.Attestations[i] = protoToAttestation(att)
	}

	if resp.GetNextCursor() != nil {
		result.NextCursor = resp.GetNextCursor().GetOffset()
	}

	return result, nil
}

// DeleteAttestation deletes an attestation by ID or hash.
func (c *GRPCClient) DeleteAttestation(ctx context.Context, orgID, namespace, id string) error {
	// Resolve orgID - derive from token if not provided
	resolvedOrgID, err := c.resolveOrgID(ctx, orgID)
	if err != nil {
		return err
	}

	// Validate orgID format
	if err := ValidateOrgID(resolvedOrgID); err != nil {
		return fmt.Errorf("invalid org ID: %w", err)
	}

	authCtx, err := c.ctxWithAuth(ctx)
	if err != nil {
		return fmt.Errorf("getting auth context: %w", err)
	}

	req := &stashv1.DeleteAttestationRequest{
		Namespace: namespace,
		OrgId:     resolvedOrgID,
	}
	if strings.HasPrefix(id, "sha256:") {
		req.Identifier = &stashv1.DeleteAttestationRequest_ContentHash{ContentHash: id}
	} else {
		req.Identifier = &stashv1.DeleteAttestationRequest_AttestationId{AttestationId: id}
	}

	_, err = c.client.DeleteAttestation(authCtx, req)
	return err
}

// UpdateAttestation updates an attestation (currently not implemented).
func (c *GRPCClient) UpdateAttestation(ctx context.Context, orgID, namespace, id string, updates map[string]interface{}) error {
	// Resolve orgID - derive from token if not provided
	resolvedOrgID, err := c.resolveOrgID(ctx, orgID)
	if err != nil {
		return err
	}

	// Validate orgID format
	if err := ValidateOrgID(resolvedOrgID); err != nil {
		return fmt.Errorf("invalid org ID: %w", err)
	}

	authCtx, err := c.ctxWithAuth(ctx)
	if err != nil {
		return fmt.Errorf("getting auth context: %w", err)
	}

	_, err = c.client.UpdateAttestation(authCtx, &stashv1.UpdateAttestationRequest{
		Namespace:     namespace,
		AttestationId: id,
		OrgId:         resolvedOrgID,
	})
	return err
}

// UploadPublicKey uploads a public key.
func (c *GRPCClient) UploadPublicKey(ctx context.Context, orgID string, keyData []byte) (string, error) {
	// orgID is sent via context metadata in GRPC, parameter kept for interface compatibility
	_ = orgID

	authCtx, err := c.ctxWithAuth(ctx)
	if err != nil {
		return "", fmt.Errorf("getting auth context: %w", err)
	}

	resp, err := c.client.UploadPublicKey(authCtx, &stashv1.UploadPublicKeyRequest{
		KeyData: keyData,
	})
	if err != nil {
		return "", err
	}
	return resp.GetKeyId(), nil
}

// ListPublicKeys lists all public keys.
func (c *GRPCClient) ListPublicKeys(ctx context.Context, orgID string) ([]*PublicKey, error) {
	// orgID is sent via context metadata in GRPC, parameter kept for interface compatibility
	_ = orgID

	authCtx, err := c.ctxWithAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting auth context: %w", err)
	}

	resp, err := c.client.ListPublicKeys(authCtx, &stashv1.ListPublicKeysRequest{})
	if err != nil {
		return nil, err
	}

	keys := make([]*PublicKey, len(resp.GetKeys()))
	for i, k := range resp.GetKeys() {
		keys[i] = &PublicKey{
			KeyID:     k.GetKeyId(),
			Algorithm: k.GetAlgorithm(),
			CreatedAt: k.GetCreatedAt().AsTime(),
		}
	}

	return keys, nil
}

// GetPublicKey retrieves a public key by ID (not in proto, uses list and filter).
func (c *GRPCClient) GetPublicKey(ctx context.Context, orgID, keyID string) (*PublicKey, error) {
	keys, err := c.ListPublicKeys(ctx, orgID)
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
func (c *GRPCClient) DeletePublicKey(ctx context.Context, orgID, keyID string) error {
	// orgID is sent via context metadata in GRPC, parameter kept for interface compatibility
	_ = orgID

	authCtx, err := c.ctxWithAuth(ctx)
	if err != nil {
		return fmt.Errorf("getting auth context: %w", err)
	}

	_, err = c.client.DeletePublicKey(authCtx, &stashv1.DeletePublicKeyRequest{
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

// PushPolicies stores one or more policy documents in a namespace. Each
// document's lineage is derived from its own id.
func (c *GRPCClient) PushPolicies(ctx context.Context, orgID, namespace string, policies [][]byte) ([]*PolicyResult, error) {
	if len(policies) == 0 {
		return nil, fmt.Errorf("no policies provided")
	}
	if len(policies) > 100 {
		return nil, fmt.Errorf("batch size exceeds maximum of 100")
	}

	// Resolve orgID - derive from token if not provided
	resolvedOrgID, err := c.resolveOrgID(ctx, orgID)
	if err != nil {
		return nil, err
	}

	// Validate orgID format
	if err := ValidateOrgID(resolvedOrgID); err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	authCtx, err := c.ctxWithAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting auth context: %w", err)
	}

	resp, err := c.client.PushPolicies(authCtx, &stashv1.PushPoliciesRequest{
		Namespace: namespace,
		Policies:  policies,
		OrgId:     resolvedOrgID,
	})
	if err != nil {
		return nil, err
	}

	results := make([]*PolicyResult, len(resp.GetResults()))
	for i, r := range resp.GetResults() {
		results[i] = protoToPolicyResult(r)
	}

	return results, nil
}

// AppendPolicy stores one document as the next version of a named lineage.
func (c *GRPCClient) AppendPolicy(ctx context.Context, orgID, namespace, lineageID string, policy []byte) (*PolicyResult, error) {
	if len(policy) == 0 {
		return nil, fmt.Errorf("no policy provided")
	}

	// Resolve orgID - derive from token if not provided
	resolvedOrgID, err := c.resolveOrgID(ctx, orgID)
	if err != nil {
		return nil, err
	}

	// Validate orgID format
	if err := ValidateOrgID(resolvedOrgID); err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}

	authCtx, err := c.ctxWithAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting auth context: %w", err)
	}

	resp, err := c.client.AppendPolicy(authCtx, &stashv1.AppendPolicyRequest{
		Namespace: namespace,
		LineageId: lineageID,
		Policy:    policy,
		OrgId:     resolvedOrgID,
	})
	if err != nil {
		return nil, err
	}

	return protoToPolicyResult(resp.GetResult()), nil
}

// GetPolicy retrieves one version of a policy lineage. A nil version reads the
// latest version; versions are 0-based, so a non-nil 0 reads version 0.
func (c *GRPCClient) GetPolicy(ctx context.Context, orgID, namespace, lineageID string, version *int64) (*Policy, []byte, error) {
	// Resolve orgID - derive from token if not provided
	resolvedOrgID, err := c.resolveOrgID(ctx, orgID)
	if err != nil {
		return nil, nil, err
	}

	// Validate orgID format
	if err := ValidateOrgID(resolvedOrgID); err != nil {
		return nil, nil, fmt.Errorf("invalid org ID: %w", err)
	}

	authCtx, err := c.ctxWithAuth(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("getting auth context: %w", err)
	}

	resp, err := c.client.GetPolicy(authCtx, &stashv1.GetPolicyRequest{
		Namespace: namespace,
		LineageId: lineageID,
		Version:   version,
		OrgId:     resolvedOrgID,
	})
	if err != nil {
		return nil, nil, err
	}

	return protoToPolicy(resp.GetPolicy()), resp.GetRaw(), nil
}

// HealthCheck checks server health.
func (c *GRPCClient) HealthCheck(ctx context.Context) (status string, components map[string]string, err error) {
	authCtx, err := c.ctxWithAuth(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("getting auth context: %w", err)
	}

	resp, err := c.client.HealthCheck(authCtx, &stashv1.HealthCheckRequest{})
	if err != nil {
		return "", nil, err
	}
	return resp.GetStatus(), resp.GetComponents(), nil
}

// DeletePolicy removes a whole policy lineage, or one version of it when version
// is non-nil, returning the number of versions deleted.
func (c *GRPCClient) DeletePolicy(ctx context.Context, orgID, namespace, lineageID string, version *int64) (int64, error) {
	resolvedOrgID, err := c.resolveOrgID(ctx, orgID)
	if err != nil {
		return 0, err
	}
	if err := ValidateOrgID(resolvedOrgID); err != nil {
		return 0, fmt.Errorf("invalid org ID: %w", err)
	}
	authCtx, err := c.ctxWithAuth(ctx)
	if err != nil {
		return 0, fmt.Errorf("getting auth context: %w", err)
	}

	resp, err := c.client.DeletePolicy(authCtx, &stashv1.DeletePolicyRequest{
		Namespace: namespace,
		LineageId: lineageID,
		Version:   version,
		OrgId:     resolvedOrgID,
	})
	if err != nil {
		return 0, err
	}
	return resp.GetDeleted(), nil
}

// ListPolicies returns one entry per lineage in a namespace, each at its latest
// version.
func (c *GRPCClient) ListPolicies(ctx context.Context, orgID, namespace string) ([]*Policy, error) {
	resolvedOrgID, err := c.resolveOrgID(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if err := ValidateOrgID(resolvedOrgID); err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}
	authCtx, err := c.ctxWithAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting auth context: %w", err)
	}

	resp, err := c.client.ListPolicies(authCtx, &stashv1.ListPoliciesRequest{
		Namespace: namespace,
		OrgId:     resolvedOrgID,
	})
	if err != nil {
		return nil, err
	}

	policies := make([]*Policy, len(resp.GetPolicies()))
	for i, p := range resp.GetPolicies() {
		policies[i] = protoToPolicy(p)
	}
	return policies, nil
}

// ListPolicyVersions returns every version of one lineage, newest first.
func (c *GRPCClient) ListPolicyVersions(ctx context.Context, orgID, namespace, lineageID string) ([]*Policy, error) {
	resolvedOrgID, err := c.resolveOrgID(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if err := ValidateOrgID(resolvedOrgID); err != nil {
		return nil, fmt.Errorf("invalid org ID: %w", err)
	}
	authCtx, err := c.ctxWithAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting auth context: %w", err)
	}

	resp, err := c.client.ListPolicyVersions(authCtx, &stashv1.ListPolicyVersionsRequest{
		Namespace: namespace,
		LineageId: lineageID,
		OrgId:     resolvedOrgID,
	})
	if err != nil {
		return nil, err
	}

	policies := make([]*Policy, len(resp.GetPolicies()))
	for i, p := range resp.GetPolicies() {
		policies[i] = protoToPolicy(p)
	}
	return policies, nil
}
