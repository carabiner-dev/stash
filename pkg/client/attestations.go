package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// UploadAttestations uploads one or more attestations to the server.
// Returns a list of upload results, one for each attestation.
// If orgID is empty, uses convenience endpoint with orgID from token.
func (c *Client) UploadAttestations(ctx context.Context, orgID, namespace string, attestations [][]byte) ([]*UploadResult, error) {
	if len(attestations) == 0 {
		return nil, fmt.Errorf("no attestations provided")
	}
	if len(attestations) > 100 {
		return nil, fmt.Errorf("batch size exceeds maximum of 100")
	}

	// Validate orgID requirements
	if orgID == "" && c.token == "" {
		return nil, fmt.Errorf("orgID required for unauthenticated requests")
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

	// Use convenience endpoint if orgID is empty and token is present
	var path string
	if orgID == "" {
		path = fmt.Sprintf("/v1/attestations/%s", namespace)
	} else {
		path = fmt.Sprintf("/v1/attestations/%s/%s", orgID, namespace)
	}

	if err := c.doRequest(ctx, "POST", path, req, &resp); err != nil {
		return nil, err
	}

	return resp.Results, nil
}

// GetAttestation retrieves an attestation by ID or hash.
// Returns the attestation metadata, raw JSON, and predicate JSON.
// If orgID is empty, uses convenience endpoint with orgID from token.
func (c *Client) GetAttestation(ctx context.Context, orgID, namespace, id string) (*Attestation, []byte, []byte, error) {
	// Validate orgID requirements
	if orgID == "" && c.token == "" {
		return nil, nil, nil, fmt.Errorf("orgID required for unauthenticated requests")
	}

	var result struct {
		Attestation *Attestation    `json:"attestation"`
		Raw         json.RawMessage `json:"raw"`
		Predicate   json.RawMessage `json:"predicate"`
	}

	// Use convenience endpoint if orgID is empty and token is present
	var path string
	if orgID == "" {
		path = fmt.Sprintf("/v1/attestations/%s/%s", namespace, id)
	} else {
		path = fmt.Sprintf("/v1/attestations/%s/%s/%s", orgID, namespace, id)
	}

	if err := c.doRequest(ctx, "GET", path, nil, &result); err != nil {
		return nil, nil, nil, err
	}

	return result.Attestation, []byte(result.Raw), []byte(result.Predicate), nil
}

// GetAttestationRaw retrieves only the raw attestation JSON by ID or hash.
// If orgID is empty, uses convenience endpoint with orgID from token.
func (c *Client) GetAttestationRaw(ctx context.Context, orgID, namespace, id string) ([]byte, error) {
	// Validate orgID requirements
	if orgID == "" && c.token == "" {
		return nil, fmt.Errorf("orgID required for unauthenticated requests")
	}

	// Use convenience endpoint if orgID is empty and token is present
	var path string
	if orgID == "" {
		path = fmt.Sprintf("/v1/attestations/%s/%s", namespace, id)
	} else {
		path = fmt.Sprintf("/v1/attestations/%s/%s/%s", orgID, namespace, id)
	}

	query := url.Values{}
	query.Set("raw", "true")

	return c.doRequestRaw(ctx, "GET", path, query)
}

// GetAttestationPredicate retrieves only the predicate JSON by ID or hash.
// If orgID is empty, uses convenience endpoint with orgID from token.
func (c *Client) GetAttestationPredicate(ctx context.Context, orgID, namespace, id string) ([]byte, error) {
	// Validate orgID requirements
	if orgID == "" && c.token == "" {
		return nil, fmt.Errorf("orgID required for unauthenticated requests")
	}

	// Use convenience endpoint if orgID is empty and token is present
	var path string
	if orgID == "" {
		path = fmt.Sprintf("/v1/attestations/%s/%s", namespace, id)
	} else {
		path = fmt.Sprintf("/v1/attestations/%s/%s/%s", orgID, namespace, id)
	}

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
// If orgID is empty, uses convenience endpoint with orgID from token.
func (c *Client) ListAttestations(ctx context.Context, orgID, namespace string, filters *Filters, cursor *Cursor) (*AttestationList, error) {
	// Validate orgID requirements
	if orgID == "" && c.token == "" {
		return nil, fmt.Errorf("orgID required for unauthenticated requests")
	}

	query := filters.toQueryParams(cursor)

	// Use convenience endpoint if orgID is empty and token is present
	var path string
	if orgID == "" {
		path = fmt.Sprintf("/v1/attestations/%s", namespace)
	} else {
		path = fmt.Sprintf("/v1/attestations/%s/%s", orgID, namespace)
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
// If orgID is empty, uses convenience endpoint with orgID from token.
func (c *Client) DeleteAttestation(ctx context.Context, orgID, namespace, id string) error {
	// Validate orgID requirements
	if orgID == "" && c.token == "" {
		return fmt.Errorf("orgID required for unauthenticated requests")
	}

	// Use convenience endpoint if orgID is empty and token is present
	var path string
	if orgID == "" {
		path = fmt.Sprintf("/v1/attestations/%s/%s", namespace, id)
	} else {
		path = fmt.Sprintf("/v1/attestations/%s/%s/%s", orgID, namespace, id)
	}

	return c.doRequest(ctx, "DELETE", path, nil, nil)
}

// UpdateAttestation updates an attestation (currently returns NOT_IMPLEMENTED).
// If orgID is empty, uses convenience endpoint with orgID from token.
func (c *Client) UpdateAttestation(ctx context.Context, orgID, namespace, id string, updates map[string]interface{}) error {
	// Validate orgID requirements
	if orgID == "" && c.token == "" {
		return fmt.Errorf("orgID required for unauthenticated requests")
	}

	// Use convenience endpoint if orgID is empty and token is present
	var path string
	if orgID == "" {
		path = fmt.Sprintf("/v1/attestations/%s/%s", namespace, id)
	} else {
		path = fmt.Sprintf("/v1/attestations/%s/%s/%s", orgID, namespace, id)
	}

	return c.doRequest(ctx, "PUT", path, updates, nil)
}
