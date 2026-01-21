package client

import (
	"context"
	"fmt"
)

// UploadPublicKey uploads a public key to the server.
// Returns the key ID assigned by the server.
func (c *Client) UploadPublicKey(ctx context.Context, keyData []byte) (string, error) {
	req := struct {
		KeyData string `json:"key_data"`
	}{
		KeyData: string(keyData),
	}

	var resp struct {
		KeyID string `json:"key_id"`
	}

	if err := c.doRequest(ctx, "POST", "/v1/publickeys", req, &resp); err != nil {
		return "", err
	}

	return resp.KeyID, nil
}

// ListPublicKeys lists all public keys for the authenticated organization.
func (c *Client) ListPublicKeys(ctx context.Context) ([]*PublicKey, error) {
	var resp struct {
		Keys []*PublicKey `json:"keys"`
	}

	if err := c.doRequest(ctx, "GET", "/v1/publickeys", nil, &resp); err != nil {
		return nil, err
	}

	return resp.Keys, nil
}

// GetPublicKey retrieves a specific public key by ID.
func (c *Client) GetPublicKey(ctx context.Context, keyID string) (*PublicKey, error) {
	path := fmt.Sprintf("/v1/publickeys/%s", keyID)

	var resp struct {
		Key *PublicKey `json:"key"`
	}

	if err := c.doRequest(ctx, "GET", path, nil, &resp); err != nil {
		return nil, err
	}

	return resp.Key, nil
}

// DeletePublicKey deletes a public key by ID.
func (c *Client) DeletePublicKey(ctx context.Context, keyID string) error {
	path := fmt.Sprintf("/v1/publickeys/%s", keyID)
	return c.doRequest(ctx, "DELETE", path, nil, nil)
}
