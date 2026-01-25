package client

import (
	"context"
	"fmt"
)

// CreateNamespace creates a new namespace in the organization.
func (c *Client) CreateNamespace(ctx context.Context, orgID, name string) (*Namespace, error) {
	req := struct {
		Name string `json:"name"`
	}{
		Name: name,
	}

	var ns Namespace
	path := fmt.Sprintf("/v1/namespaces/%s", orgID)
	if err := c.doRequest(ctx, "POST", path, req, &ns); err != nil {
		return nil, err
	}

	return &ns, nil
}

// GetNamespace retrieves a namespace by name.
func (c *Client) GetNamespace(ctx context.Context, orgID, name string) (*Namespace, error) {
	var ns Namespace
	path := fmt.Sprintf("/v1/namespaces/%s/%s", orgID, name)
	if err := c.doRequest(ctx, "GET", path, nil, &ns); err != nil {
		return nil, err
	}

	return &ns, nil
}

// ListNamespaces lists all namespaces for an organization.
func (c *Client) ListNamespaces(ctx context.Context, orgID string) ([]*Namespace, error) {
	var resp struct {
		Namespaces []*Namespace `json:"namespaces"`
	}

	path := fmt.Sprintf("/v1/namespaces/%s", orgID)
	if err := c.doRequest(ctx, "GET", path, nil, &resp); err != nil {
		return nil, err
	}

	return resp.Namespaces, nil
}

// DeleteNamespace deletes a namespace.
func (c *Client) DeleteNamespace(ctx context.Context, orgID, name string) error {
	path := fmt.Sprintf("/v1/namespaces/%s/%s", orgID, name)
	return c.doRequest(ctx, "DELETE", path, nil, nil)
}
