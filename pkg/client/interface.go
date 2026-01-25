package client

import (
	"context"
)

// StashClient is the interface for interacting with the Stash API.
// Both GRPCClient and (legacy) RESTClient implement this interface.
type StashClient interface {
	// UploadAttestations uploads one or more attestations to a namespace.
	UploadAttestations(ctx context.Context, orgID, namespace string, attestations [][]byte) ([]*UploadResult, error)

	// GetAttestation retrieves an attestation by ID.
	GetAttestation(ctx context.Context, orgID, namespace, id string) (*Attestation, []byte, []byte, error)

	// GetAttestationRaw retrieves only the raw attestation JSON.
	GetAttestationRaw(ctx context.Context, orgID, namespace, id string) ([]byte, error)

	// GetAttestationPredicate retrieves only the predicate JSON.
	GetAttestationPredicate(ctx context.Context, orgID, namespace, id string) ([]byte, error)

	// GetAttestationByHash retrieves an attestation by content hash.
	GetAttestationByHash(ctx context.Context, orgID, namespace, hash string) (*Attestation, []byte, []byte, error)

	// GetAttestationByPredicateHash retrieves an attestation by predicate hash.
	GetAttestationByPredicateHash(ctx context.Context, orgID, namespace, hash string) (*Attestation, []byte, []byte, error)

	// ListAttestations lists attestations with optional filters and pagination.
	ListAttestations(ctx context.Context, orgID, namespace string, filters *Filters, cursor *Cursor) (*AttestationList, error)

	// DeleteAttestation deletes an attestation.
	DeleteAttestation(ctx context.Context, orgID, namespace, id string) error

	// UpdateAttestation updates an attestation.
	UpdateAttestation(ctx context.Context, orgID, namespace, id string, updates map[string]interface{}) error

	// CreateNamespace creates a new namespace.
	CreateNamespace(ctx context.Context, orgID, name string) (*Namespace, error)

	// GetNamespace retrieves a namespace by name.
	GetNamespace(ctx context.Context, orgID, name string) (*Namespace, error)

	// ListNamespaces lists all namespaces for an organization.
	ListNamespaces(ctx context.Context, orgID string) ([]*Namespace, error)

	// DeleteNamespace deletes a namespace.
	DeleteNamespace(ctx context.Context, orgID, name string) error

	// UploadPublicKey uploads a public key.
	UploadPublicKey(ctx context.Context, keyData []byte) (string, error)

	// ListPublicKeys lists all public keys.
	ListPublicKeys(ctx context.Context) ([]*PublicKey, error)

	// GetPublicKey retrieves a public key by ID.
	GetPublicKey(ctx context.Context, keyID string) (*PublicKey, error)

	// DeletePublicKey deletes a public key.
	DeletePublicKey(ctx context.Context, keyID string) error
}

// Ensure both client types implement the interface.
var _ StashClient = (*Client)(nil)
var _ StashClient = (*GRPCClient)(nil)
