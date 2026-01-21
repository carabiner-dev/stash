// Package config provides client configuration.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config holds client configuration.
type Config struct {
	// BaseURL is the Stash server URL.
	BaseURL string

	// Token is the bearer token for authentication.
	Token string
}

// DefaultConfig returns the default client configuration.
func DefaultConfig() *Config {
	return &Config{
		BaseURL: "http://localhost:8080",
	}
}

// LoadConfig loads configuration from environment variables and token file.
func LoadConfig() (*Config, error) {
	cfg := DefaultConfig()

	// Load base URL from environment
	if url := os.Getenv("STASH_URL"); url != "" {
		cfg.BaseURL = url
	}

	// Load token from environment or token file
	token, err := loadToken()
	if err != nil {
		return nil, err
	}
	cfg.Token = token

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
