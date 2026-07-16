package client

import (
	"context"
)

// StashClient is the interface for interacting with the Stash API.
// Both GRPCClient and (legacy) RESTClient implement this interface.
//
// All methods require explicit orgID - convenience endpoints have been removed.
// The orgID parameter must always be specified.
type StashClient interface {
	// UploadAttestations uploads one or more attestations to a namespace.
	// orgID must be specified - convenience endpoints have been removed.
	UploadAttestations(ctx context.Context, orgID, namespace string, attestations [][]byte) ([]*UploadResult, error)

	// GetAttestation retrieves an attestation by ID.
	// orgID must be specified - convenience endpoints have been removed.
	GetAttestation(ctx context.Context, orgID, namespace, id string) (*Attestation, []byte, []byte, error)

	// GetAttestationRaw retrieves only the raw attestation JSON.
	// orgID must be specified - convenience endpoints have been removed.
	GetAttestationRaw(ctx context.Context, orgID, namespace, id string) ([]byte, error)

	// GetAttestationPredicate retrieves only the predicate JSON.
	// orgID must be specified - convenience endpoints have been removed.
	GetAttestationPredicate(ctx context.Context, orgID, namespace, id string) ([]byte, error)

	// GetAttestationByHash retrieves an attestation by content hash.
	// orgID must be specified - convenience endpoints have been removed.
	GetAttestationByHash(ctx context.Context, orgID, namespace, hash string) (*Attestation, []byte, []byte, error)

	// GetAttestationByPredicateHash retrieves an attestation by predicate hash.
	// orgID must be specified - convenience endpoints have been removed.
	GetAttestationByPredicateHash(ctx context.Context, orgID, namespace, hash string) (*Attestation, []byte, []byte, error)

	// ListAttestations lists attestations with optional filters and pagination.
	// orgID must be specified - convenience endpoints have been removed.
	ListAttestations(ctx context.Context, orgID, namespace string, filters *Filters, cursor *Cursor) (*AttestationList, error)

	// DeleteAttestation deletes an attestation.
	// orgID must be specified - convenience endpoints have been removed.
	DeleteAttestation(ctx context.Context, orgID, namespace, id string) error

	// UpdateAttestation updates an attestation.
	// orgID must be specified - convenience endpoints have been removed.
	UpdateAttestation(ctx context.Context, orgID, namespace, id string, updates map[string]interface{}) error

	// CreateNamespace creates a new namespace.
	// orgID must be specified - convenience endpoints have been removed.
	CreateNamespace(ctx context.Context, orgID, name string) (*Namespace, error)

	// GetNamespace retrieves a namespace by name.
	// orgID must be specified - convenience endpoints have been removed.
	GetNamespace(ctx context.Context, orgID, name string) (*Namespace, error)

	// ListNamespaces lists all namespaces for an organization.
	// orgID must be specified - convenience endpoints have been removed.
	ListNamespaces(ctx context.Context, orgID string) ([]*Namespace, error)

	// DeleteNamespace deletes a namespace.
	// orgID must be specified - convenience endpoints have been removed.
	DeleteNamespace(ctx context.Context, orgID, name string) error

	// UploadPublicKey uploads a public key.
	// orgID must be specified - convenience endpoints have been removed.
	UploadPublicKey(ctx context.Context, orgID string, keyData []byte) (string, error)

	// ListPublicKeys lists all public keys.
	// orgID must be specified - convenience endpoints have been removed.
	ListPublicKeys(ctx context.Context, orgID string) ([]*PublicKey, error)

	// GetPublicKey retrieves a public key by ID.
	// orgID must be specified - convenience endpoints have been removed.
	GetPublicKey(ctx context.Context, orgID, keyID string) (*PublicKey, error)

	// DeletePublicKey deletes a public key.
	// orgID must be specified - convenience endpoints have been removed.
	DeletePublicKey(ctx context.Context, orgID, keyID string) error

	// PushPolicies stores one or more policy documents in a namespace. Each
	// document's lineage is derived from its own id. Batches are capped at 100.
	// orgID must be specified.
	PushPolicies(ctx context.Context, orgID, namespace string, policies [][]byte) ([]*PolicyResult, error)

	// AppendPolicy stores one document as the next version of a named lineage.
	// orgID must be specified.
	AppendPolicy(ctx context.Context, orgID, namespace, lineageID string, policy []byte) (*PolicyResult, error)

	// GetPolicy retrieves one version of a policy lineage. A nil version reads
	// the latest version; versions are 0-based, so a non-nil 0 reads version 0.
	// It returns the policy metadata and the raw stored document.
	// orgID must be specified.
	GetPolicy(ctx context.Context, orgID, namespace, lineageID string, version *int64) (*Policy, []byte, error)

	// DeletePolicy removes a whole policy lineage or one of its versions.
	DeletePolicy(ctx context.Context, orgID, namespace, lineageID string, version *int64) (int64, error)
}

// Ensure both client types implement the interface.
var (
	_ StashClient = (*Client)(nil)
	_ StashClient = (*GRPCClient)(nil)
)
