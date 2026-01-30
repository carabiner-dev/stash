// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package cli provides CLI commands for the stash client.
package cli

import (
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
	flagURL      string
	flagToken    string
	flagOrg      string
	flagUseREST  bool
	flagInsecure bool
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
	rootCmd.PersistentFlags().StringVar(&flagURL, "url", "", "Stash server URL (default from STASH_URL or localhost:8080)")
	rootCmd.PersistentFlags().StringVar(&flagToken, "token", "", "Authentication token (default from STASH_TOKEN or ~/.stash/token)")
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
		// Check if it's just missing token - allow for dev mode without auth
		if os.Getenv("STASH_TOKEN") == "" {
			// Use default config without token for dev mode
			cfg = config.DefaultConfig()
			cfg.Token = ""
		} else {
			return nil, nil, err
		}
	}

	// Override with flags if provided
	if flagURL != "" {
		cfg.BaseURL = flagURL
	}
	if flagToken != "" {
		cfg.Token = flagToken
	}

	// Use REST client if --rest flag is set
	if flagUseREST {
		return client.NewClientFromConfig(cfg), func() {}, nil
	}

	// Use gRPC client by default
	grpcClient, err := client.NewGRPCClientFromConfig(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("creating gRPC client: %w", err)
	}

	// Return cleanup function to close connection
	cleanup := func() {
		grpcClient.Close()
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
