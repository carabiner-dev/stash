package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// UploadAttestations uploads one or more attestations to the server.
// Returns a list of upload results, one for each attestation.
func (c *Client) UploadAttestations(ctx context.Context, attestations [][]byte) ([]*UploadResult, error) {
	if len(attestations) == 0 {
		return nil, fmt.Errorf("no attestations provided")
	}
	if len(attestations) > 100 {
		return nil, fmt.Errorf("batch size exceeds maximum of 100")
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

	if err := c.doRequest(ctx, "POST", "/v1/attestations", req, &resp); err != nil {
		return nil, err
	}

	return resp.Results, nil
}

// GetAttestation retrieves an attestation by ID or hash.
// Returns the attestation metadata, raw JSON, and predicate JSON.
func (c *Client) GetAttestation(ctx context.Context, id string) (*Attestation, []byte, []byte, error) {
	var result struct {
		Attestation *Attestation    `json:"attestation"`
		Raw         json.RawMessage `json:"raw"`
		Predicate   json.RawMessage `json:"predicate"`
	}

	path := fmt.Sprintf("/v1/attestations/%s", id)
	if err := c.doRequest(ctx, "GET", path, nil, &result); err != nil {
		return nil, nil, nil, err
	}

	return result.Attestation, []byte(result.Raw), []byte(result.Predicate), nil
}

// GetAttestationRaw retrieves only the raw attestation JSON by ID or hash.
func (c *Client) GetAttestationRaw(ctx context.Context, id string) ([]byte, error) {
	path := fmt.Sprintf("/v1/attestations/%s", id)
	query := url.Values{}
	query.Set("raw", "true")

	return c.doRequestRaw(ctx, "GET", path, query)
}

// GetAttestationPredicate retrieves only the predicate JSON by ID or hash.
func (c *Client) GetAttestationPredicate(ctx context.Context, id string) ([]byte, error) {
	path := fmt.Sprintf("/v1/attestations/%s", id)
	query := url.Values{}
	query.Set("predicate", "true")

	return c.doRequestRaw(ctx, "GET", path, query)
}

// GetAttestationByHash retrieves an attestation by its content hash.
func (c *Client) GetAttestationByHash(ctx context.Context, hash string) (*Attestation, []byte, []byte, error) {
	return c.GetAttestation(ctx, hash)
}

// GetAttestationByPredicateHash retrieves an attestation by its predicate hash.
func (c *Client) GetAttestationByPredicateHash(ctx context.Context, hash string) (*Attestation, []byte, []byte, error) {
	return c.GetAttestation(ctx, hash)
}

// ListAttestations lists attestations with optional filters and pagination.
func (c *Client) ListAttestations(ctx context.Context, filters *Filters, cursor *Cursor) (*AttestationList, error) {
	query := filters.toQueryParams(cursor)

	body, err := c.doRequestRaw(ctx, "GET", "/v1/attestations", query)
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
func (c *Client) DeleteAttestation(ctx context.Context, id string) error {
	path := fmt.Sprintf("/v1/attestations/%s", id)
	return c.doRequest(ctx, "DELETE", path, nil, nil)
}

// UpdateAttestation updates an attestation (currently returns NOT_IMPLEMENTED).
func (c *Client) UpdateAttestation(ctx context.Context, id string, updates map[string]interface{}) error {
	path := fmt.Sprintf("/v1/attestations/%s", id)
	return c.doRequest(ctx, "PUT", path, updates, nil)
}
