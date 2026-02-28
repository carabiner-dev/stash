// Package config provides client configuration.
package config

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/carabiner-dev/deadrop/pkg/client/credentials"
	"github.com/carabiner-dev/deadrop/pkg/client/exchange"
)

// Config holds client configuration.
type Config struct {
	// BaseURL is the Stash server URL.
	BaseURL string

	// Token is the bearer token for authentication (deprecated: use credentials manager).
	// If set, this takes precedence over credentials manager.
	Token string

	// AuthServer is the URL of the authentication server for token exchange.
	AuthServer string

	// UseCredentialsManager indicates whether to use the credentials manager.
	// If false, uses static token from Token field.
	UseCredentialsManager bool

	// tokenSource is the service token source for automatic token exchange (internal).
	tokenSource credentials.TokenSource
}

// DefaultConfig returns the default client configuration.
func DefaultConfig() *Config {
	return &Config{
		BaseURL:               "http://localhost:8080",
		AuthServer:            "https://auth.carabiner.dev",
		UseCredentialsManager: true,
	}
}

// LoadConfig loads configuration from environment variables and token file.
func LoadConfig() (*Config, error) {
	cfg := DefaultConfig()

	// Load base URL from environment
	if url := os.Getenv("STASH_URL"); url != "" {
		cfg.BaseURL = url
	}

	// Load auth server from environment
	if authServer := os.Getenv("STASH_AUTH_SERVER"); authServer != "" {
		cfg.AuthServer = authServer
	}

	// Check for explicit token (backwards compatibility / testing)
	token, err := loadToken()
	if err == nil && token != "" {
		// Explicit token provided - use static mode
		cfg.Token = token
		cfg.UseCredentialsManager = false
	} else {
		// No explicit token - use credentials manager
		cfg.UseCredentialsManager = true
	}

	return cfg, nil
}

// loadToken loads the token from environment variable or ~/.stash/token file.
func loadToken() (string, error) {
	// Try environment variable first
	if token := os.Getenv("STASH_TOKEN"); token != "" {
		return token, nil
	}

	// Try token file
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("getting home directory: %w", err)
	}

	tokenPath := filepath.Join(home, ".stash", "token")
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("no token found (set STASH_TOKEN or create ~/.stash/token)")
		}
		return "", fmt.Errorf("reading token file: %w", err)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("token file is empty")
	}

	return token, nil
}

// SaveToken saves the token to ~/.stash/token.
func SaveToken(token string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("getting home directory: %w", err)
	}

	stashDir := filepath.Join(home, ".stash")
	if err := os.MkdirAll(stashDir, 0700); err != nil {
		return fmt.Errorf("creating .stash directory: %w", err)
	}

	tokenPath := filepath.Join(stashDir, "token")
	if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		return fmt.Errorf("writing token file: %w", err)
	}

	return nil
}

// renewingIdentitySource is a TokenSource that automatically renews expired identity tokens.
type renewingIdentitySource struct {
	serverURL string
}

func (r *renewingIdentitySource) Token(ctx context.Context) (string, error) {
	// LoadIdentityWithRenewal already handles disk caching and automatic renewal
	token, _, _, err := credentials.LoadIdentityWithRenewal(ctx, r.serverURL)
	if err != nil {
		return "", err
	}
	return token, nil
}

// InitializeCredentialsManager initializes the service token source for this config.
// The token source will exchange the Carabiner identity token for a Stash-specific token.
// It extracts the orgs from the identity token and requests resource claims for all of them.
func (c *Config) InitializeCredentialsManager(ctx context.Context, orgID string) error {
	if !c.UseCredentialsManager {
		return nil // Using static token, no token source needed
	}

	if c.tokenSource != nil {
		return nil // Already initialized
	}

	// Load the identity token to extract orgs
	identityToken, _, _, err := credentials.LoadIdentityWithRenewal(ctx, c.AuthServer)
	if err != nil {
		return fmt.Errorf("loading identity token: %w", err)
	}

	// Parse orgs from the identity token
	orgs, err := parseOrgsFromToken(identityToken)
	if err != nil {
		return fmt.Errorf("parsing orgs from identity token: %w", err)
	}

	// Build exchange request with audience "stash" and resource claims for all orgs
	req := &exchange.ExchangeRequest{
		Audience: []string{"stash"},
	}

	// Add resource claims for all orgs the user has access to
	// Format: /v1/{orgID}/* - request access to all namespaces in each org
	if len(orgs) > 0 {
		resources := make([]string, len(orgs))
		for i, org := range orgs {
			resources[i] = fmt.Sprintf("/v1/%s/*", org)
		}
		req.Resource = resources
	}

	// Create renewing identity source that handles token refresh
	identitySource := &renewingIdentitySource{
		serverURL: c.AuthServer,
	}

	// Create service token source with persistence, caching, and auto-renewing identity source
	source, err := credentials.NewServiceTokenSource(
		req,
		c.AuthServer,
		credentials.WithServicePersistence(),        // Enable disk persistence for cross-process caching
		credentials.WithServiceRefreshBuffer(0.1),   // Refresh at 90% of token lifetime (more conservative)
		credentials.WithServiceIdentitySource(identitySource),
	)
	if err != nil {
		return fmt.Errorf("creating service token source: %w", err)
	}

	c.tokenSource = source
	return nil
}

// parseOrgsFromToken extracts the orgs claim from a JWT token.
func parseOrgsFromToken(tokenString string) ([]string, error) {
	// Split JWT into parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT payload: %w", err)
	}

	// Parse the JSON payload
	var claims struct {
		Orgs []string `json:"orgs"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parsing JWT claims: %w", err)
	}

	return claims.Orgs, nil
}

// DeriveOrgFromToken attempts to derive a single org ID from the token.
// Returns the org ID if the token has exactly one org, or empty string if:
// - Token has no orgs
// - Token has multiple orgs (ambiguous - user must specify)
func (c *Config) DeriveOrgFromToken(ctx context.Context) (string, error) {
	// Get the service token (which has the org-specific resource claims)
	token, err := c.GetToken(ctx)
	if err != nil {
		return "", fmt.Errorf("getting token: %w", err)
	}

	// Parse namespaces from token to determine orgs
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decoding JWT payload: %w", err)
	}

	var claims struct {
		Namespaces []string `json:"namespaces"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("parsing JWT claims: %w", err)
	}

	// Extract unique org IDs from namespace URLs
	orgIDs := make(map[string]bool)
	for _, ns := range claims.Namespaces {
		// Parse URL like "https://stash.dev.carabiner.dev/v1/puerco/*"
		// Extract the org ID (part after /v1/)
		parts := strings.Split(ns, "/")
		if len(parts) >= 5 && parts[3] == "v1" {
			orgID := parts[4]
			orgIDs[orgID] = true
		}
	}

	// If exactly one org, return it
	if len(orgIDs) == 1 {
		for orgID := range orgIDs {
			return orgID, nil
		}
	}

	// Multiple orgs or no orgs - cannot determine
	return "", nil
}

// GetToken returns a valid token, either static or from the service token source.
func (c *Config) GetToken(ctx context.Context) (string, error) {
	// If using static token, return it directly
	if !c.UseCredentialsManager || c.Token != "" {
		return c.Token, nil
	}

	// Ensure token source is initialized (without org restriction if not set during init)
	if c.tokenSource == nil {
		if err := c.InitializeCredentialsManager(ctx, ""); err != nil {
			return "", err
		}
	}

	// Get token from service token source
	token, err := c.tokenSource.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("getting token from service token source: %w", err)
	}

	return token, nil
}

// Close closes the token source if active.
func (c *Config) Close() error {
	// ServiceTokenSource doesn't need explicit closing
	return nil
}
