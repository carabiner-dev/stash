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
	flagURL   string
	flagToken string
)

// Execute runs the root command.
func Execute() error {
	rootCmd := &cobra.Command{
		Use:   "stash",
		Short: "Stash attestation storage client",
		Long: `Stash CLI provides commands for interacting with the Stash attestation storage system.
Upload, retrieve, query, and manage attestations and public keys.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&flagURL, "url", "", "Stash server URL (default from STASH_URL or http://localhost:8080)")
	rootCmd.PersistentFlags().StringVar(&flagToken, "token", "", "Authentication token (default from STASH_TOKEN or ~/.stash/token)")

	// Add subcommands
	rootCmd.AddCommand(NewUploadCommand())
	rootCmd.AddCommand(NewReadCommand())
	rootCmd.AddCommand(NewListCommand())
	rootCmd.AddCommand(NewDeleteCommand())
	rootCmd.AddCommand(NewUpdateCommand())
	rootCmd.AddCommand(NewVerifyCommand())
	rootCmd.AddCommand(NewPublicKeyCommand())
	rootCmd.AddCommand(NewVersionCommand())

	return rootCmd.Execute()
}

// getClient creates a client from global flags and environment.
func getClient() (*client.Client, error) {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, err
	}

	// Override with flags if provided
	if flagURL != "" {
		cfg.BaseURL = flagURL
	}
	if flagToken != "" {
		cfg.Token = flagToken
	}

	return client.NewClientFromConfig(cfg), nil
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

// exitError prints an error and exits.
func exitError(err error) {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}
