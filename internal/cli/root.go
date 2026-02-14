// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package cli provides CLI commands for the stash client.
package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/carabiner-dev/stash/pkg/client"
	"github.com/carabiner-dev/stash/pkg/client/config"
)

var (
	// Version information (set by build)
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

// Global flags
var (
	flagServer     string
	flagAuthServer string
	flagToken      string
	flagOrg        string
	flagUseREST    bool
	flagInsecure   bool
)

// Execute runs the root command.
func Execute() error {
	rootCmd := &cobra.Command{
		Use:   "stash",
		Short: "Stash attestation storage client",
		Long: `Stash CLI provides commands for interacting with the Stash attestation storage system.
Push, retrieve, query, and manage attestations and public keys.

By default, the client uses gRPC for communication. Use --rest to fall back to REST API.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&flagServer, "server", "", "Stash server URL https://stash.carabiner.dev")
	rootCmd.PersistentFlags().StringVar(&flagAuthServer, "auth-server", "", "Auth server URL for token exchange (default: https://auth.carabiner.dev)")
	rootCmd.PersistentFlags().StringVar(&flagToken, "token", "", "Override: explicit authentication token (disables automatic token management)")
	rootCmd.PersistentFlags().StringVar(&flagOrg, "org", "", "Organization ID (default from STASH_ORG)")
	rootCmd.PersistentFlags().BoolVar(&flagUseREST, "rest", false, "Use REST API instead of gRPC")
	rootCmd.PersistentFlags().BoolVar(&flagInsecure, "insecure", false, "Disable TLS for gRPC connections (for development)")

	// Add subcommands
	AddPushCommand(rootCmd)
	AddGetCommand(rootCmd)
	AddListCommand(rootCmd)
	AddDeleteCommand(rootCmd)
	AddUpdateCommand(rootCmd)
	AddVerifyCommand(rootCmd)
	AddPublicKeyCommand(rootCmd)
	rootCmd.AddCommand(NewVersionCommand())

	return rootCmd.Execute()
}

// getClient creates a client from global flags and environment.
// By default, returns a gRPC client. Use --rest flag for REST client.
func getClient() (client.StashClient, func(), error) {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		// If no credentials found, create default config
		// The credentials manager will handle the error when trying to get a token
		cfg = config.DefaultConfig()
	}

	// Override with flags if provided
	if flagServer != "" {
		cfg.BaseURL = flagServer
	}
	if flagAuthServer != "" {
		cfg.AuthServer = flagAuthServer
	}
	if flagToken != "" {
		// Explicit token provided - disable credentials manager
		cfg.Token = flagToken
		cfg.UseCredentialsManager = false
	}

	// Initialize credentials manager if needed
	if cfg.UseCredentialsManager {
		ctx := context.Background()
		if err := cfg.InitializeCredentialsManager(ctx); err != nil {
			return nil, nil, fmt.Errorf("initializing credentials manager: %w", err)
		}
	}

	// Use REST client if --rest flag is set
	if flagUseREST {
		restClient := client.NewClientFromConfig(cfg)
		cleanup := func() {
			restClient.Close()
		}
		return restClient, cleanup, nil
	}

	// Use gRPC client by default
	grpcClient, err := client.NewGRPCClientFromConfig(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("creating gRPC client: %w", err)
	}

	// Return cleanup function to close both client and config
	cleanup := func() {
		grpcClient.Close()
		cfg.Close()
	}

	return grpcClient, cleanup, nil
}

// getOrgID returns the organization ID from flag or environment.
// Returns an error if orgID is not set.
func getOrgID() (string, error) {
	// Check flag first
	if flagOrg != "" {
		return flagOrg, nil
	}

	// Check environment variable
	if envOrg := os.Getenv("STASH_ORG"); envOrg != "" {
		return envOrg, nil
	}

	return "", fmt.Errorf("organization ID is required (use --org flag or STASH_ORG environment variable)")
}

// NewVersionCommand creates the version command.
func NewVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("stash %s\n", Version)
			fmt.Printf("Git commit: %s\n", GitCommit)
			fmt.Printf("Build date: %s\n", BuildDate)
		},
	}
}
