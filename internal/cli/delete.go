// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = (*DeleteOptions)(nil)

// DeleteOptions holds the options for the delete command.
type DeleteOptions struct {
	ClientOptions
}

var defaultDeleteOptions = DeleteOptions{
	ClientOptions: defaultClientOptions,
}

func (o *DeleteOptions) Validate() error {
	return errors.Join(
		o.ClientOptions.Validate(),
	)
}

func (o *DeleteOptions) Config() *command.OptionsSetConfig {
	return nil
}

func (o *DeleteOptions) AddFlags(cmd *cobra.Command) {
	o.ClientOptions.AddFlags(cmd)
}

// AddDelete adds the delete command to the parent.
func AddDelete(parent *cobra.Command) {
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
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]

			// Get organization ID
			orgID, err := opts.GetOrg()
			if err != nil {
				return err
			}

			// Get client
			c, cleanup, err := opts.NewClient()
			if err != nil {
				return fmt.Errorf("creating client: %w", err)
			}
			defer cleanup()

			// Delete attestation
			fmt.Printf("Deleting attestation %s...\n", id)
			if err := c.DeleteAttestation(cmd.Context(), orgID, "", id); err != nil {
				return fmt.Errorf("deleting attestation: %w", err)
			}

			fmt.Println("✓ Attestation deleted successfully")

			return nil
		},
	}

	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}
