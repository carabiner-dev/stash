package client

import (
	"context"
	"fmt"
)

// CreateNamespace creates a new namespace in the organization.
// orgID must be specified - convenience endpoints have been removed.
func (c *Client) CreateNamespace(ctx context.Context, orgID, name string) (*Namespace, error) {
	if orgID == "" {
		return nil, fmt.Errorf("orgID is required")
	}

	req := struct {
		Name string `json:"name"`
	}{
		Name: name,
	}

	var ns Namespace

	// All requests use explicit orgID endpoint
	path := fmt.Sprintf("/v1/namespaces/%s", orgID)

	if err := c.doRequest(ctx, "POST", path, req, &ns); err != nil {
		return nil, err
	}

	return &ns, nil
}

// GetNamespace retrieves a namespace by name.
// orgID must be specified - convenience endpoints have been removed.
func (c *Client) GetNamespace(ctx context.Context, orgID, name string) (*Namespace, error) {
	if orgID == "" {
		return nil, fmt.Errorf("orgID is required")
	}

	var ns Namespace

	// All requests use explicit orgID endpoint
	path := fmt.Sprintf("/v1/namespaces/%s/%s", orgID, name)

	if err := c.doRequest(ctx, "GET", path, nil, &ns); err != nil {
		return nil, err
	}

	return &ns, nil
}

// ListNamespaces lists all namespaces for an organization.
// orgID must be specified - convenience endpoints have been removed.
func (c *Client) ListNamespaces(ctx context.Context, orgID string) ([]*Namespace, error) {
	if orgID == "" {
		return nil, fmt.Errorf("orgID is required")
	}

	var resp struct {
		Namespaces []*Namespace `json:"namespaces"`
	}

	// All requests use explicit orgID endpoint
	path := fmt.Sprintf("/v1/namespaces/%s", orgID)

	if err := c.doRequest(ctx, "GET", path, nil, &resp); err != nil {
		return nil, err
	}

	return resp.Namespaces, nil
}

// DeleteNamespace deletes a namespace.
// orgID must be specified - convenience endpoints have been removed.
func (c *Client) DeleteNamespace(ctx context.Context, orgID, name string) error {
	if orgID == "" {
		return fmt.Errorf("orgID is required")
	}

	// All requests use explicit orgID endpoint
	path := fmt.Sprintf("/v1/namespaces/%s/%s", orgID, name)

	return c.doRequest(ctx, "DELETE", path, nil, nil)
}

// SetNamespaceVisibility opens a namespace's attestations to anyone, or
// closes them again. "_" names the default namespace on the REST path.
func (c *Client) SetNamespaceVisibility(ctx context.Context, orgID, name string, public bool) (*Namespace, error) {
	if orgID == "" {
		return nil, fmt.Errorf("orgID is required")
	}

	req := struct {
		Public bool `json:"public"`
	}{Public: public}

	var ns Namespace
	if name == "" {
		name = "_"
	}
	path := fmt.Sprintf("/v1/namespaces/%s/%s/visibility", orgID, name)
	if err := c.doRequest(ctx, "PUT", path, req, &ns); err != nil {
		return nil, err
	}
	return &ns, nil
}
