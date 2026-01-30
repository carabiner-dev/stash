package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)


// UploadAttestations uploads one or more attestations to the server.
// Returns a list of upload results, one for each attestation.
// orgID must be specified - convenience endpoints have been removed.
func (c *Client) UploadAttestations(ctx context.Context, orgID, namespace string, attestations [][]byte) ([]*UploadResult, error) {
	if len(attestations) == 0 {
		return nil, fmt.Errorf("no attestations provided")
	}
	if len(attestations) > 100 {
		return nil, fmt.Errorf("batch size exceeds maximum of 100")
	}
	if orgID == "" {
		return nil, fmt.Errorf("orgID is required")
	}

	// Convert [][]byte to []json.RawMessage for proper JSON marshaling
	rawAttestations := make([]json.RawMessage, len(attestations))
	for i, att := range attestations {
		rawAttestations[i] = json.RawMessage(att)
	}

	req := struct {
		Attestations []json.RawMessage `json:"attestations"`
	}{
		Attestations: rawAttestations,
	}

	var resp struct {
		Results []*UploadResult `json:"results"`
	}

	// Normalize namespace: empty string means default namespace
	ns := normalizeNamespace(namespace)

	// All requests use explicit orgID endpoint
	// If namespace is empty, omit it from URL (uses default namespace)
	var path string
	if ns == "" {
		path = fmt.Sprintf("/v1/attestations/%s", orgID)
	} else {
		path = fmt.Sprintf("/v1/attestations/%s/%s", orgID, ns)
	}

	if err := c.doRequest(ctx, "POST", path, req, &resp); err != nil {
		return nil, err
	}

	return resp.Results, nil
}

// GetAttestation retrieves an attestation by ID or hash.
// Returns the attestation metadata, raw JSON, and predicate JSON.
// orgID must be specified - convenience endpoints have been removed.
func (c *Client) GetAttestation(ctx context.Context, orgID, namespace, id string) (*Attestation, []byte, []byte, error) {
	if orgID == "" {
		return nil, nil, nil, fmt.Errorf("orgID is required")
	}

	var result struct {
		Attestation *Attestation    `json:"attestation"`
		Raw         json.RawMessage `json:"raw"`
		Predicate   json.RawMessage `json:"predicate"`
	}

	// Normalize namespace: empty string becomes "_" for URL paths
	ns := normalizeNamespace(namespace)

	// All requests use explicit orgID endpoint
	path := fmt.Sprintf("/v1/attestations/%s/%s/%s", orgID, ns, id)

	if err := c.doRequest(ctx, "GET", path, nil, &result); err != nil {
		return nil, nil, nil, err
	}

	return result.Attestation, []byte(result.Raw), []byte(result.Predicate), nil
}

// GetAttestationRaw retrieves only the raw attestation JSON by ID or hash.
// orgID must be specified - convenience endpoints have been removed.
func (c *Client) GetAttestationRaw(ctx context.Context, orgID, namespace, id string) ([]byte, error) {
	if orgID == "" {
		return nil, fmt.Errorf("orgID is required")
	}

	// Normalize namespace: empty string becomes "_" for URL paths
	ns := normalizeNamespace(namespace)

	// All requests use explicit orgID endpoint
	path := fmt.Sprintf("/v1/attestations/%s/%s/%s", orgID, ns, id)

	query := url.Values{}
	query.Set("raw", "true")

	return c.doRequestRaw(ctx, "GET", path, query)
}

// GetAttestationPredicate retrieves only the predicate JSON by ID or hash.
// orgID must be specified - convenience endpoints have been removed.
func (c *Client) GetAttestationPredicate(ctx context.Context, orgID, namespace, id string) ([]byte, error) {
	if orgID == "" {
		return nil, fmt.Errorf("orgID is required")
	}

	// Normalize namespace: empty string becomes "_" for URL paths
	ns := normalizeNamespace(namespace)

	// All requests use explicit orgID endpoint
	path := fmt.Sprintf("/v1/attestations/%s/%s/%s", orgID, ns, id)

	query := url.Values{}
	query.Set("predicate", "true")

	return c.doRequestRaw(ctx, "GET", path, query)
}

// GetAttestationByHash retrieves an attestation by its content hash.
func (c *Client) GetAttestationByHash(ctx context.Context, orgID, namespace, hash string) (*Attestation, []byte, []byte, error) {
	return c.GetAttestation(ctx, orgID, namespace, hash)
}

// GetAttestationByPredicateHash retrieves an attestation by its predicate hash.
func (c *Client) GetAttestationByPredicateHash(ctx context.Context, orgID, namespace, hash string) (*Attestation, []byte, []byte, error) {
	return c.GetAttestation(ctx, orgID, namespace, hash)
}

// ListAttestations lists attestations with optional filters and pagination.
// orgID must be specified - convenience endpoints have been removed.
func (c *Client) ListAttestations(ctx context.Context, orgID, namespace string, filters *Filters, cursor *Cursor) (*AttestationList, error) {
	if orgID == "" {
		return nil, fmt.Errorf("orgID is required")
	}

	query := filters.toQueryParams(cursor)

	// Normalize namespace: empty string means default namespace
	ns := normalizeNamespace(namespace)

	// All requests use explicit orgID endpoint
	// If namespace is empty, omit it from URL (uses default namespace)
	var path string
	if ns == "" {
		path = fmt.Sprintf("/v1/attestations/%s", orgID)
	} else {
		path = fmt.Sprintf("/v1/attestations/%s/%s", orgID, ns)
	}

	body, err := c.doRequestRaw(ctx, "GET", path, query)
	if err != nil {
		return nil, err
	}

	var result AttestationList
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshaling response: %w", err)
	}

	return &result, nil
}

// DeleteAttestation deletes an attestation by ID or hash.
// orgID must be specified - convenience endpoints have been removed.
func (c *Client) DeleteAttestation(ctx context.Context, orgID, namespace, id string) error {
	// Validate orgID requirements
	if orgID == "" && c.token == "" {
		return fmt.Errorf("orgID required for unauthenticated requests")
	}

	// Normalize namespace: empty string becomes "_" for URL paths
	ns := normalizeNamespace(namespace)

	// All requests use explicit orgID endpoint
	path := fmt.Sprintf("/v1/attestations/%s/%s/%s", orgID, ns, id)

	return c.doRequest(ctx, "DELETE", path, nil, nil)
}

// UpdateAttestation updates an attestation (currently returns NOT_IMPLEMENTED).
// orgID must be specified - convenience endpoints have been removed.
func (c *Client) UpdateAttestation(ctx context.Context, orgID, namespace, id string, updates map[string]interface{}) error {
	// Validate orgID requirements
	if orgID == "" && c.token == "" {
		return fmt.Errorf("orgID required for unauthenticated requests")
	}

	// Normalize namespace: empty string becomes "_" for URL paths
	ns := normalizeNamespace(namespace)

	// All requests use explicit orgID endpoint
	path := fmt.Sprintf("/v1/attestations/%s/%s/%s", orgID, ns, id)

	return c.doRequest(ctx, "PUT", path, updates, nil)
}
