package client

import (
	"net/url"
	"strconv"
	"time"
)

// Filters represents query filters for listing attestations.
type Filters struct {
	// PredicateType filters by predicate type.
	PredicateType string

	// SubjectName filters by exact subject name.
	SubjectName string

	// SubjectDigest filters by subject digest (algorithm -> value).
	SubjectDigest map[string]string

	// SubjectURI filters by exact subject URI.
	SubjectURI string

	// SubjectNameRegex filters by subject name regex (max 256 chars).
	SubjectNameRegex string

	// SubjectURIRegex filters by subject URI regex (max 256 chars).
	SubjectURIRegex string

	// SignerIdentity filters by signer identity.
	SignerIdentity string

	// SignedOnly filters to only signed attestations.
	SignedOnly bool

	// ValidatedOnly filters to only validated attestations.
	ValidatedOnly bool
}

// Cursor represents pagination cursor.
type Cursor struct {
	// Limit is the maximum number of results to return (default 50, max 1000).
	Limit int

	// Token is the pagination cursor token.
	Token string
}

// toQueryParams converts filters and cursor to URL query parameters.
func (f *Filters) toQueryParams(cursor *Cursor) url.Values {
	params := url.Values{}

	if f != nil {
		if f.PredicateType != "" {
			params.Set("predicate_type", f.PredicateType)
		}
		if f.SubjectName != "" {
			params.Set("subject.name", f.SubjectName)
		}
		for algo, value := range f.SubjectDigest {
			params.Set("subject.digest."+algo, value)
		}
		if f.SubjectURI != "" {
			params.Set("subject.uri", f.SubjectURI)
		}
		if f.SubjectNameRegex != "" {
			params.Set("subject_regex.name", f.SubjectNameRegex)
		}
		if f.SubjectURIRegex != "" {
			params.Set("subject_regex.uri", f.SubjectURIRegex)
		}
		if f.SignerIdentity != "" {
			params.Set("signer_identity", f.SignerIdentity)
		}
		if f.SignedOnly {
			params.Set("signed", "true")
		}
		if f.ValidatedOnly {
			params.Set("validated", "true")
		}
	}

	if cursor != nil {
		if cursor.Limit > 0 {
			params.Set("limit", strconv.Itoa(cursor.Limit))
		}
		if cursor.Token != "" {
			params.Set("cursor", cursor.Token)
		}
	}

	return params
}

// Attestation represents an attestation metadata.
type Attestation struct {
	ID                   string            `json:"id"`
	OrgID                string            `json:"org_id"`
	ContentHash          string            `json:"content_hash"`
	PredicateHash        string            `json:"predicate_hash"`
	PredicateType        string            `json:"predicate_type"`
	Signed               bool              `json:"signed"`
	Validated            bool              `json:"validated"`
	ValidationError      string            `json:"validation_error,omitempty"`
	SignerIdentities     []string          `json:"signer_identities,omitempty"`
	Subjects             []Subject         `json:"subjects,omitempty"`
	CreatedAt            time.Time         `json:"created_at"`
	PredicateTimestamp   *time.Time        `json:"predicate_timestamp,omitempty"`
	UpdatedAt            time.Time         `json:"updated_at"`
	RawStoragePath       string            `json:"raw_storage_path,omitempty"`
	PredicateStoragePath string            `json:"predicate_storage_path,omitempty"`
}

// Subject represents an attestation subject.
type Subject struct {
	Name             string            `json:"name"`
	DigestAlgorithm  string            `json:"digest_algorithm"`
	DigestValue      string            `json:"digest_value"`
	URI              string            `json:"uri,omitempty"`
	DownloadLocation string            `json:"download_location,omitempty"`
	MediaType        string            `json:"media_type,omitempty"`
	Annotations      map[string]string `json:"annotations,omitempty"`
}

// AttestationList represents a list of attestations with pagination.
type AttestationList struct {
	Attestations []*Attestation `json:"attestations"`
	NextCursor   string         `json:"next_cursor,omitempty"`
	Total        int            `json:"total,omitempty"`
}

// UploadResult represents the result of uploading an attestation.
type UploadResult struct {
	AttestationID string `json:"attestation_id"`
	ContentHash   string `json:"content_hash"`
	Existed       bool   `json:"existed"`
	Error         string `json:"error,omitempty"`
}

// PublicKey represents a public key.
type PublicKey struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	KeyID     string    `json:"key_id"`
	Algorithm string    `json:"algorithm"`
	CreatedAt time.Time `json:"created_at"`
}
