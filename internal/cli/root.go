// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package cli provides CLI commands for the stash client.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	// Version information (set by build)
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
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

	// Add subcommands
	AddAuth(rootCmd)
	AddPush(rootCmd)
	AddGet(rootCmd)
	AddList(rootCmd)
	AddDelete(rootCmd)
	AddUpdate(rootCmd)
	AddVerify(rootCmd)
	AddPublicKey(rootCmd)
	addVersion(rootCmd)

	return rootCmd.Execute()
}

// addVersion adds the version command to the parent.
func addVersion(parent *cobra.Command) {
	parent.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("stash %s\n", Version)
			fmt.Printf("Git commit: %s\n", GitCommit)
			fmt.Printf("Build date: %s\n", BuildDate)
		},
	})
}
