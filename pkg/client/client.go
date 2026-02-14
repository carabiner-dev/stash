// Package client provides a Go client for the Stash API.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/carabiner-dev/stash/pkg/client/config"
)

// Client is the Stash API client.
type Client struct {
	config     *config.Config
	httpClient *http.Client
}

// NewClient creates a new Stash client with the given base URL and token.
// Deprecated: Use NewClientFromConfig for better token management.
func NewClient(baseURL, token string) *Client {
	cfg := &config.Config{
		BaseURL:               baseURL,
		Token:                 token,
		UseCredentialsManager: false, // Static token mode
	}
	return &Client{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewClientFromConfig creates a new client from configuration.
func NewClientFromConfig(cfg *config.Config) *Client {
	return &Client{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewClientFromEnv creates a new client from environment variables.
func NewClientFromEnv() (*Client, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, err
	}
	return NewClientFromConfig(cfg), nil
}

// Close closes the client and its credentials manager if active.
func (c *Client) Close() error {
	if c.config != nil {
		return c.config.Close()
	}
	return nil
}

// normalizeNamespace handles empty namespace for URL paths.
// Empty namespace means the default namespace - we can omit it from the URL path.
// The server accepts both /v1/attestations/{orgID} and /v1/attestations/{orgID}/_
func normalizeNamespace(namespace string) string {
	// Empty string stays empty - will be omitted from URL
	// Underscore and other values stay as-is
	return namespace
}

// doRequest performs an HTTP request with authentication.
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshaling request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	reqURL, err := url.JoinPath(c.config.BaseURL, path)
	if err != nil {
		return fmt.Errorf("building request URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	// Get token (either static or from credentials manager)
	token, err := c.config.GetToken(ctx)
	if err != nil {
		return fmt.Errorf("getting authentication token: %w", err)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("performing request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	// Check for errors
	if resp.StatusCode >= 400 {
		var apiErr APIError
		if err := json.Unmarshal(respBody, &apiErr); err != nil {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
		}
		return &apiErr
	}

	// Unmarshal result if provided
	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("unmarshaling response: %w", err)
		}
	}

	return nil
}

// doRequestRaw performs an HTTP request and returns the raw response body.
func (c *Client) doRequestRaw(ctx context.Context, method, path string, query url.Values) ([]byte, error) {
	reqURL, err := url.JoinPath(c.config.BaseURL, path)
	if err != nil {
		return nil, fmt.Errorf("building request URL: %w", err)
	}

	if len(query) > 0 {
		u, _ := url.Parse(reqURL)
		u.RawQuery = query.Encode()
		reqURL = u.String()
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Get token (either static or from credentials manager)
	token, err := c.config.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting authentication token: %w", err)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("performing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var apiErr APIError
		if err := json.Unmarshal(body, &apiErr); err != nil {
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
		}
		return nil, &apiErr
	}

	return body, nil
}

// APIError represents an API error response.
type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (e *APIError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("API error %d: %s (%s)", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("API error %d: %s", e.Code, e.Message)
}
