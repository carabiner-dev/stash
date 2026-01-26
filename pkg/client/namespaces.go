package client

import (
	"context"
	"fmt"
)

// CreateNamespace creates a new namespace in the organization.
// If orgID is empty, uses convenience endpoint with orgID from token.
func (c *Client) CreateNamespace(ctx context.Context, orgID, name string) (*Namespace, error) {
	// Validate orgID requirements
	if orgID == "" && c.token == "" {
		return nil, fmt.Errorf("orgID required for unauthenticated requests")
	}

	req := struct {
		Name string `json:"name"`
	}{
		Name: name,
	}

	var ns Namespace

	// Use convenience endpoint if orgID is empty and token is present
	var path string
	if orgID == "" {
		path = "/v1/namespaces"
	} else {
		path = fmt.Sprintf("/v1/namespaces/%s", orgID)
	}

	if err := c.doRequest(ctx, "POST", path, req, &ns); err != nil {
		return nil, err
	}

	return &ns, nil
}

// GetNamespace retrieves a namespace by name.
// If orgID is empty, uses convenience endpoint with orgID from token.
func (c *Client) GetNamespace(ctx context.Context, orgID, name string) (*Namespace, error) {
	// Validate orgID requirements
	if orgID == "" && c.token == "" {
		return nil, fmt.Errorf("orgID required for unauthenticated requests")
	}

	var ns Namespace

	// Use convenience endpoint if orgID is empty and token is present
	var path string
	if orgID == "" {
		path = fmt.Sprintf("/v1/namespaces/%s", name)
	} else {
		path = fmt.Sprintf("/v1/namespaces/%s/%s", orgID, name)
	}

	if err := c.doRequest(ctx, "GET", path, nil, &ns); err != nil {
		return nil, err
	}

	return &ns, nil
}

// ListNamespaces lists all namespaces for an organization.
// If orgID is empty, uses convenience endpoint with orgID from token.
func (c *Client) ListNamespaces(ctx context.Context, orgID string) ([]*Namespace, error) {
	// Validate orgID requirements
	if orgID == "" && c.token == "" {
		return nil, fmt.Errorf("orgID required for unauthenticated requests")
	}

	var resp struct {
		Namespaces []*Namespace `json:"namespaces"`
	}

	// Use convenience endpoint if orgID is empty and token is present
	var path string
	if orgID == "" {
		path = "/v1/namespaces"
	} else {
		path = fmt.Sprintf("/v1/namespaces/%s", orgID)
	}

	if err := c.doRequest(ctx, "GET", path, nil, &resp); err != nil {
		return nil, err
	}

	return resp.Namespaces, nil
}

// DeleteNamespace deletes a namespace.
// If orgID is empty, uses convenience endpoint with orgID from token.
func (c *Client) DeleteNamespace(ctx context.Context, orgID, name string) error {
	// Validate orgID requirements
	if orgID == "" && c.token == "" {
		return fmt.Errorf("orgID required for unauthenticated requests")
	}

	// Use convenience endpoint if orgID is empty and token is present
	var path string
	if orgID == "" {
		path = fmt.Sprintf("/v1/namespaces/%s", name)
	} else {
		path = fmt.Sprintf("/v1/namespaces/%s/%s", orgID, name)
	}

	return c.doRequest(ctx, "DELETE", path, nil, nil)
}
