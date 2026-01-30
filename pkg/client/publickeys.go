package client

import (
	"context"
	"fmt"
)

// UploadPublicKey uploads a public key to the server.
// Returns the key ID assigned by the server.
// orgID must be specified - convenience endpoints have been removed.
func (c *Client) UploadPublicKey(ctx context.Context, orgID string, keyData []byte) (string, error) {
	if orgID == "" {
		return "", fmt.Errorf("orgID is required")
	}

	req := struct {
		KeyData string `json:"key_data"`
	}{
		KeyData: string(keyData),
	}

	var resp struct {
		KeyID string `json:"key_id"`
	}

	path := fmt.Sprintf("/v1/publickeys/%s", orgID)
	if err := c.doRequest(ctx, "POST", path, req, &resp); err != nil {
		return "", err
	}

	return resp.KeyID, nil
}

// ListPublicKeys lists all public keys for the specified organization.
// orgID must be specified - convenience endpoints have been removed.
func (c *Client) ListPublicKeys(ctx context.Context, orgID string) ([]*PublicKey, error) {
	if orgID == "" {
		return nil, fmt.Errorf("orgID is required")
	}

	var resp struct {
		Keys []*PublicKey `json:"keys"`
	}

	path := fmt.Sprintf("/v1/publickeys/%s", orgID)
	if err := c.doRequest(ctx, "GET", path, nil, &resp); err != nil {
		return nil, err
	}

	return resp.Keys, nil
}

// GetPublicKey retrieves a specific public key by ID.
// orgID must be specified - convenience endpoints have been removed.
func (c *Client) GetPublicKey(ctx context.Context, orgID, keyID string) (*PublicKey, error) {
	if orgID == "" {
		return nil, fmt.Errorf("orgID is required")
	}

	path := fmt.Sprintf("/v1/publickeys/%s/%s", orgID, keyID)

	var resp struct {
		Key *PublicKey `json:"key"`
	}

	if err := c.doRequest(ctx, "GET", path, nil, &resp); err != nil {
		return nil, err
	}

	return resp.Key, nil
}

// DeletePublicKey deletes a public key by ID.
// orgID must be specified - convenience endpoints have been removed.
func (c *Client) DeletePublicKey(ctx context.Context, orgID, keyID string) error {
	if orgID == "" {
		return fmt.Errorf("orgID is required")
	}

	path := fmt.Sprintf("/v1/publickeys/%s/%s", orgID, keyID)
	return c.doRequest(ctx, "DELETE", path, nil, nil)
}
