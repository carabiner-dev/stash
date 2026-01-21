// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = (*DeleteOptions)(nil)

// DeleteOptions holds the options for the delete command.
type DeleteOptions struct{}

var defaultDeleteOptions = &DeleteOptions{}

func (o *DeleteOptions) Validate() error {
	return nil
}

func (o *DeleteOptions) Config() *command.OptionsSetConfig {
	return nil
}

func (o *DeleteOptions) AddFlags(cmd *cobra.Command) {}

// AddDeleteCommand adds the delete command to the parent.
func AddDeleteCommand(parent *cobra.Command) {
	opts := defaultDeleteOptions
	cmd := &cobra.Command{
		Use:   "delete <attestation-id|hash>",
		Short: "Delete an attestation from Stash",
		Long: `Delete an attestation by ID or hash from the Stash server.

This permanently removes the attestation and all its metadata.

Examples:
  # Delete by attestation ID
  stash delete abc123

  # Delete by content hash
  stash delete sha256:a1b2c3...`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}

			id := args[0]

			// Get client
			c, err := getClient()
			if err != nil {
				return fmt.Errorf("creating client: %w", err)
			}

			// Delete attestation
			fmt.Printf("Deleting attestation %s...\n", id)
			if err := c.DeleteAttestation(cmd.Context(), id); err != nil {
				return fmt.Errorf("deleting attestation: %w", err)
			}

			fmt.Println("✓ Attestation deleted successfully")

			return nil
		},
	}

	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}
