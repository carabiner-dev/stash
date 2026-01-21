package client

import (
	"context"
)

// StashClient is the interface for interacting with the Stash API.
// Both GRPCClient and (legacy) RESTClient implement this interface.
type StashClient interface {
	// UploadAttestations uploads one or more attestations.
	UploadAttestations(ctx context.Context, attestations [][]byte) ([]*UploadResult, error)

	// GetAttestation retrieves an attestation by ID.
	GetAttestation(ctx context.Context, id string) (*Attestation, []byte, []byte, error)

	// GetAttestationRaw retrieves only the raw attestation JSON.
	GetAttestationRaw(ctx context.Context, id string) ([]byte, error)

	// GetAttestationPredicate retrieves only the predicate JSON.
	GetAttestationPredicate(ctx context.Context, id string) ([]byte, error)

	// GetAttestationByHash retrieves an attestation by content hash.
	GetAttestationByHash(ctx context.Context, hash string) (*Attestation, []byte, []byte, error)

	// GetAttestationByPredicateHash retrieves an attestation by predicate hash.
	GetAttestationByPredicateHash(ctx context.Context, hash string) (*Attestation, []byte, []byte, error)

	// ListAttestations lists attestations with optional filters and pagination.
	ListAttestations(ctx context.Context, filters *Filters, cursor *Cursor) (*AttestationList, error)

	// DeleteAttestation deletes an attestation.
	DeleteAttestation(ctx context.Context, id string) error

	// UpdateAttestation updates an attestation.
	UpdateAttestation(ctx context.Context, id string, updates map[string]interface{}) error

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
