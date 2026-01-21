// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = (*ReadOptions)(nil)

// ReadOptions holds the options for the read command.
type ReadOptions struct {
	Raw       bool
	Predicate bool
}

var defaultReadOptions = &ReadOptions{
	Raw:       false,
	Predicate: false,
}

func (o *ReadOptions) Validate() error {
	return nil
}

func (o *ReadOptions) Config() *command.OptionsSetConfig {
	return nil
}

func (o *ReadOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.Raw, "raw", false, "Return only raw attestation JSON")
	cmd.Flags().BoolVar(&o.Predicate, "predicate", false, "Return only predicate JSON")
}

// AddReadCommand adds the read command to the parent.
func AddReadCommand(parent *cobra.Command) {
	opts := defaultReadOptions
	cmd := &cobra.Command{
		Use:   "read <attestation-id|hash>",
		Short: "Read an attestation from Stash",
		Long: `Read an attestation by ID or hash from the Stash server.

By default, returns both the attestation metadata, raw JSON, and predicate JSON.
Use --raw to get only the raw attestation JSON.
Use --predicate to get only the predicate JSON.

Examples:
  # Read attestation with metadata
  stash read abc123

  # Read only raw attestation
  stash read abc123 --raw

  # Read only predicate
  stash read abc123 --predicate

  # Read by content hash
  stash read sha256:a1b2c3...

  # Read by predicate hash
  stash read predicate:sha256:d4e5f6...`,
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

			// Handle --raw flag
			if opts.Raw {
				data, err := c.GetAttestationRaw(cmd.Context(), id)
				if err != nil {
					return fmt.Errorf("reading attestation: %w", err)
				}
				fmt.Println(string(data))
				return nil
			}

			// Handle --predicate flag
			if opts.Predicate {
				data, err := c.GetAttestationPredicate(cmd.Context(), id)
				if err != nil {
					return fmt.Errorf("reading predicate: %w", err)
				}
				fmt.Println(string(data))
				return nil
			}

			// Get full attestation
			attestation, raw, predicate, err := c.GetAttestation(cmd.Context(), id)
			if err != nil {
				return fmt.Errorf("reading attestation: %w", err)
			}

			// Print metadata
			fmt.Printf("Attestation ID:    %s\n", attestation.ID)
			fmt.Printf("Org ID:            %s\n", attestation.OrgID)
			fmt.Printf("Content Hash:      %s\n", attestation.ContentHash)
			fmt.Printf("Predicate Hash:    %s\n", attestation.PredicateHash)
			fmt.Printf("Predicate Type:    %s\n", attestation.PredicateType)
			fmt.Printf("Signed:            %v\n", attestation.Signed)
			fmt.Printf("Validated:         %v\n", attestation.Validated)
			if attestation.ValidationError != "" {
				fmt.Printf("Validation Error:  %s\n", attestation.ValidationError)
			}
			if len(attestation.SignerIdentities) > 0 {
				fmt.Printf("Signer Identities: %v\n", attestation.SignerIdentities)
			}
			fmt.Printf("Created At:        %s\n", attestation.CreatedAt.Format("2006-01-02 15:04:05 MST"))
			if attestation.PredicateTimestamp != nil {
				fmt.Printf("Predicate Time:    %s\n", attestation.PredicateTimestamp.Format("2006-01-02 15:04:05 MST"))
			}
			fmt.Printf("Updated At:        %s\n", attestation.UpdatedAt.Format("2006-01-02 15:04:05 MST"))

			// Print subjects
			if len(attestation.Subjects) > 0 {
				fmt.Printf("\nSubjects (%d):\n", len(attestation.Subjects))
				for i, subject := range attestation.Subjects {
					fmt.Printf("  %d. %s\n", i+1, subject.Name)
					fmt.Printf("     Digest: %s:%s\n", subject.DigestAlgorithm, subject.DigestValue)
					if subject.URI != "" {
						fmt.Printf("     URI: %s\n", subject.URI)
					}
				}
			}

			// Print raw attestation
			fmt.Println("\n=== Raw Attestation ===")
			var rawIndented interface{}
			if err := json.Unmarshal(raw, &rawIndented); err == nil {
				prettyRaw, _ := json.MarshalIndent(rawIndented, "", "  ")
				fmt.Println(string(prettyRaw))
			} else {
				fmt.Println(string(raw))
			}

			// Print predicate
			fmt.Println("\n=== Predicate ===")
			var predicateIndented interface{}
			if err := json.Unmarshal(predicate, &predicateIndented); err == nil {
				prettyPredicate, _ := json.MarshalIndent(predicateIndented, "", "  ")
				fmt.Println(string(prettyPredicate))
			} else {
				fmt.Println(string(predicate))
			}

			return nil
		},
	}

	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}
