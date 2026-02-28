// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"os"

	"github.com/carabiner-dev/command"
	"github.com/carabiner-dev/stash/pkg/client"
	"github.com/carabiner-dev/stash/pkg/client/config"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = (*ClientOptions)(nil)

var defaultClientOptions = ClientOptions{
	Server:     "",
	AuthServer: "",
	Token:      "",
	Org:        "",
	UseREST:    false,
	Insecure:   false,
}

// ClientOptions contains the common client connection options.
type ClientOptions struct {
	Server     string
	AuthServer string
	Token      string
	Org        string
	UseREST    bool
	Insecure   bool
}

func (co *ClientOptions) Config() *command.OptionsSetConfig {
	return nil
}

func (co *ClientOptions) Validate() error {
	return nil
}

func (co *ClientOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&co.Server, "server", "", "Stash server URL (default: https://stash.carabiner.dev)")
	cmd.PersistentFlags().StringVar(&co.AuthServer, "auth-server", "", "Auth server URL for token exchange (default: https://auth.carabiner.dev)")
	cmd.PersistentFlags().StringVar(&co.Token, "token", "", "Override: explicit authentication token (disables automatic token management)")
	cmd.PersistentFlags().StringVar(&co.Org, "org", "", "Organization ID (default from STASH_ORG)")
	cmd.PersistentFlags().BoolVar(&co.UseREST, "rest", false, "Use REST API instead of gRPC")
	cmd.PersistentFlags().BoolVar(&co.Insecure, "insecure", false, "Disable TLS for gRPC connections (for development)")
}

// NewClient creates a new Stash client based on the configured options.
func (co *ClientOptions) NewClient(ctx context.Context, orgID, namespace string) (client.StashClient, func(), error) {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		// If no credentials found, create default config
		cfg = config.DefaultConfig()
	}

	// Override with options if provided
	if co.Server != "" {
		cfg.BaseURL = co.Server
	}
	if co.AuthServer != "" {
		cfg.AuthServer = co.AuthServer
	}
	if co.Token != "" {
		// Explicit token provided - disable credentials manager
		cfg.Token = co.Token
		cfg.UseCredentialsManager = false
	}

	// Initialize credentials manager if needed
	if cfg.UseCredentialsManager {
		if err := cfg.InitializeCredentialsManager(ctx, orgID); err != nil {
			return nil, nil, err
		}
	}

	// Use REST client if requested
	if co.UseREST {
		restClient := client.NewClientFromConfig(cfg)
		cleanup := func() {
			restClient.Close()
		}
		return restClient, cleanup, nil
	}

	// Use gRPC client by default
	grpcClient, err := client.NewGRPCClientFromConfig(cfg)
	if err != nil {
		return nil, nil, err
	}

	// Return cleanup function to close both client and config
	cleanup := func() {
		grpcClient.Close()
		cfg.Close()
	}

	return grpcClient, cleanup, nil
}

// GetOrg returns the organization ID from options or environment.
func (co *ClientOptions) GetOrg() (string, error) {
	// Check option first
	if co.Org != "" {
		return co.Org, nil
	}

	// Check environment variable
	if envOrg := getEnvOrg(); envOrg != "" {
		return envOrg, nil
	}

	return "", errors.New("organization ID is required (use --org flag or STASH_ORG environment variable)")
}

// getEnvOrg returns the organization ID from environment variable.
func getEnvOrg() string {
	return os.Getenv("STASH_ORG")
}
