// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
)

// PushPolicies stores one or more policy documents in a namespace. Each
// document's lineage is derived from its own id. Returns one result per
// submitted document, in order.
// orgID must be specified.
//
//nolint:dupl // intentionally mirrors the REST UploadAttestations flow
func (c *Client) PushPolicies(ctx context.Context, orgID, namespace string, policies [][]byte) ([]*PolicyResult, error) {
	if len(policies) == 0 {
		return nil, fmt.Errorf("no policies provided")
	}
	if len(policies) > 100 {
		return nil, fmt.Errorf("batch size exceeds maximum of 100")
	}
	if orgID == "" {
		return nil, fmt.Errorf("orgID is required")
	}

	// Convert [][]byte to []json.RawMessage for proper JSON marshaling.
	rawPolicies := make([]json.RawMessage, len(policies))
	for i, p := range policies {
		rawPolicies[i] = json.RawMessage(p)
	}

	req := struct {
		Policies []json.RawMessage `json:"policies"`
	}{
		Policies: rawPolicies,
	}

	var resp struct {
		Results []*PolicyResult `json:"results"`
	}

	// Normalize namespace: empty string means default namespace.
	ns := normalizeNamespace(namespace)

	// If namespace is empty, omit it from URL (uses default namespace).
	var path string
	if ns == "" {
		path = fmt.Sprintf("/v1/policies/%s", orgID)
	} else {
		path = fmt.Sprintf("/v1/policies/%s/%s", orgID, ns)
	}

	if err := c.doRequest(ctx, "POST", path, req, &resp); err != nil {
		return nil, err
	}

	return resp.Results, nil
}

// AppendPolicy stores one document as the next version of a named lineage.
// orgID must be specified.
func (c *Client) AppendPolicy(ctx context.Context, orgID, namespace, lineageID string, policy []byte) (*PolicyResult, error) {
	if len(policy) == 0 {
		return nil, fmt.Errorf("no policy provided")
	}
	if orgID == "" {
		return nil, fmt.Errorf("orgID is required")
	}

	req := struct {
		Policy json.RawMessage `json:"policy"`
	}{
		Policy: json.RawMessage(policy),
	}

	var resp struct {
		Result *PolicyResult `json:"result"`
	}

	// Normalize namespace: empty string becomes "_" for URL paths.
	ns := normalizeNamespace(namespace)
	if ns == "" {
		ns = "_"
	}

	path := fmt.Sprintf("/v1/policies/%s/%s/%s", orgID, ns, lineageID)

	if err := c.doRequest(ctx, "POST", path, req, &resp); err != nil {
		return nil, err
	}

	return resp.Result, nil
}

// GetPolicy retrieves one version of a policy lineage. A nil version reads the
// latest version; versions are 0-based, so a non-nil 0 reads version 0.
// It returns the policy metadata and the raw stored document.
// orgID must be specified.
func (c *Client) GetPolicy(ctx context.Context, orgID, namespace, lineageID string, version *int64) (*Policy, []byte, error) {
	if orgID == "" {
		return nil, nil, fmt.Errorf("orgID is required")
	}

	var result struct {
		Policy *Policy         `json:"policy"`
		Raw    json.RawMessage `json:"raw"`
	}

	// Normalize namespace: empty string becomes "_" for URL paths.
	ns := normalizeNamespace(namespace)
	if ns == "" {
		ns = "_"
	}

	path := fmt.Sprintf("/v1/policies/%s/%s/%s", orgID, ns, lineageID)

	// A nil version means latest; only send an explicit version when set (0 is
	// a valid version, distinct from "latest").
	if version != nil {
		path = fmt.Sprintf("%s?version=%s", path, strconv.FormatInt(*version, 10))
	}

	if err := c.doRequest(ctx, "GET", path, nil, &result); err != nil {
		return nil, nil, err
	}

	return result.Policy, []byte(result.Raw), nil
}

// DeletePolicy removes a whole policy lineage, or one version of it when version
// is non-nil (0 is a valid version, distinct from "whole lineage"), returning
// the number of versions deleted.
func (c *Client) DeletePolicy(ctx context.Context, orgID, namespace, lineageID string, version *int64) (int64, error) {
	if orgID == "" {
		return 0, fmt.Errorf("orgID is required")
	}

	ns := normalizeNamespace(namespace)
	if ns == "" {
		ns = "_"
	}
	path := fmt.Sprintf("/v1/policies/%s/%s/%s", orgID, ns, lineageID)
	if version != nil {
		path = fmt.Sprintf("%s?version=%s", path, strconv.FormatInt(*version, 10))
	}

	var result struct {
		Deleted int64 `json:"deleted"`
	}
	if err := c.doRequest(ctx, "DELETE", path, nil, &result); err != nil {
		return 0, err
	}
	return result.Deleted, nil
}
