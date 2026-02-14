// Package config provides client configuration.
package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/carabiner-dev/deadrop/pkg/client/credentials"
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

	// credentialsManager is the credentials manager instance (internal).
	credentialsManager *credentials.Manager
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

// InitializeCredentialsManager initializes the credentials manager for this config.
// The manager will exchange the Carabiner ID token for a Stash-specific token.
func (c *Config) InitializeCredentialsManager(ctx context.Context) error {
	if !c.UseCredentialsManager {
		return nil // Using static token, no manager needed
	}

	if c.credentialsManager != nil {
		return nil // Already initialized
	}

	// Create default token source (checks CARABINER_CREDENTIALS env and ~/.carabiner/credentials file)
	tokenSource, err := credentials.DefaultTokenSource()
	if err != nil {
		return fmt.Errorf("creating token source: %w", err)
	}

	// Create credentials manager
	manager, err := credentials.NewManager(
		ctx,
		credentials.WithTokenSource(tokenSource),
		credentials.WithServer(c.AuthServer),
	)
	if err != nil {
		return fmt.Errorf("creating credentials manager: %w", err)
	}

	// Determine audience from BaseURL
	audience := c.BaseURL
	if audience == "" {
		audience = "https://stash.carabiner.dev"
	}

	// Register stash session with appropriate audience
	spec := credentials.ExchangeSpec{
		Audience: []string{audience},
	}

	if err := manager.Register(ctx, "stash", spec); err != nil {
		manager.Close()
		return fmt.Errorf("registering stash session: %w", err)
	}

	c.credentialsManager = manager
	return nil
}

// GetToken returns a valid token, either static or from the credentials manager.
func (c *Config) GetToken(ctx context.Context) (string, error) {
	// If using static token, return it directly
	if !c.UseCredentialsManager || c.Token != "" {
		return c.Token, nil
	}

	// Ensure credentials manager is initialized
	if c.credentialsManager == nil {
		if err := c.InitializeCredentialsManager(ctx); err != nil {
			return "", err
		}
	}

	// Get token from credentials manager
	token, err := c.credentialsManager.Token(ctx, "stash")
	if err != nil {
		return "", fmt.Errorf("getting token from credentials manager: %w", err)
	}

	return token, nil
}

// Close closes the credentials manager if active.
func (c *Config) Close() error {
	if c.credentialsManager != nil {
		return c.credentialsManager.Close()
	}
	return nil
}
