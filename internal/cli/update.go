// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = (*UpdateOptions)(nil)

// UpdateOptions holds the options for the update command.
type UpdateOptions struct{}

var defaultUpdateOptions = &UpdateOptions{}

func (o *UpdateOptions) Validate() error {
	return nil
}

func (o *UpdateOptions) Config() *command.OptionsSetConfig {
	return nil
}

func (o *UpdateOptions) AddFlags(cmd *cobra.Command) {}

// AddUpdateCommand adds the update command to the parent.
func AddUpdateCommand(parent *cobra.Command) {
	opts := defaultUpdateOptions
	cmd := &cobra.Command{
		Use:   "update <attestation-id>",
		Short: "Update an attestation (not implemented)",
		Long: `Update attestation metadata.

Note: This operation is not currently implemented by the server.

Examples:
  # Attempt to update an attestation
  stash update abc123`,
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

			// Attempt update (will return NOT_IMPLEMENTED)
			updates := map[string]interface{}{}
			if err := c.UpdateAttestation(cmd.Context(), id, updates); err != nil {
				return fmt.Errorf("updating attestation: %w", err)
			}

			fmt.Println("✓ Attestation updated successfully")

			return nil
		},
	}

	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}
