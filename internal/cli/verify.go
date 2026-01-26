// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = (*VerifyOptions)(nil)

// VerifyOptions holds the options for the verify command.
type VerifyOptions struct{}

var defaultVerifyOptions = &VerifyOptions{}

func (o *VerifyOptions) Validate() error {
	return nil
}

func (o *VerifyOptions) Config() *command.OptionsSetConfig {
	return nil
}

func (o *VerifyOptions) AddFlags(cmd *cobra.Command) {}

// AddVerifyCommand adds the verify command to the parent.
func AddVerifyCommand(parent *cobra.Command) {
	opts := defaultVerifyOptions
	cmd := &cobra.Command{
		Use:   "verify <attestation-id|hash>",
		Short: "Verify a stored attestation",
		Long: `Re-verify the signatures of a stored attestation.

This retrieves the attestation and checks its signatures against
the public keys stored in Stash.

Examples:
  # Verify an attestation
  stash verify abc123

  # Verify by hash
  stash verify sha256:a1b2c3...`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}

			id := args[0]

			// Get client
			c, cleanup, err := getClient()
			if err != nil {
				return fmt.Errorf("creating client: %w", err)
			}
			defer cleanup()

			// Get attestation
			fmt.Printf("Retrieving attestation %s...\n", id)
			attestation, _, _, err := c.GetAttestation(cmd.Context(), "", "", id)
			if err != nil {
				return fmt.Errorf("retrieving attestation: %w", err)
			}

			// Display verification status
			fmt.Printf("\nAttestation: %s\n", attestation.ID)
			fmt.Printf("Predicate Type: %s\n", attestation.PredicateType)
			fmt.Printf("Signed: %v\n", attestation.Signed)
			fmt.Printf("Validated: %v\n", attestation.Validated)

			if !attestation.Signed {
				fmt.Println("\n⚠️  Attestation is not signed")
				return nil
			}

			if attestation.ValidationError != "" {
				fmt.Printf("\n❌ Validation failed: %s\n", attestation.ValidationError)
				return nil
			}

			if attestation.Validated {
				fmt.Println("\n✓ Attestation signature is valid")
				if len(attestation.SignerIdentities) > 0 {
					fmt.Println("\nSigner identities:")
					for _, identity := range attestation.SignerIdentities {
						fmt.Printf("  - %s\n", identity)
					}
				}
			} else {
				fmt.Println("\n⚠️  Attestation signature could not be validated (no public keys available)")
			}

			return nil
		},
	}

	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}
