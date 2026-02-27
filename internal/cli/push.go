// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = (*PushOptions)(nil)

// PushOptions holds the options for the push command.
type PushOptions struct {
	ClientOptions
	Stdin     bool
	Namespace string
}

var defaultPushOptions = PushOptions{
	ClientOptions: defaultClientOptions,
	Stdin:         false,
	Namespace:     "",
}

func (o *PushOptions) Validate() error {
	return errors.Join(
		o.ClientOptions.Validate(),
	)
}

func (o *PushOptions) Config() *command.OptionsSetConfig {
	return nil
}

func (o *PushOptions) AddFlags(cmd *cobra.Command) {
	o.ClientOptions.AddFlags(cmd)
	cmd.Flags().BoolVar(&o.Stdin, "stdin", false, "Read attestation from stdin")
	cmd.Flags().StringVarP(&o.Namespace, "namespace", "n", "", "Namespace for attestations (default: empty)")
}

// AddPush adds the push command to the parent.
func AddPush(parent *cobra.Command) {
	opts := defaultPushOptions

	cmd := &cobra.Command{
		Use:   "push [file...]",
		Short: "Push attestations to Stash",
		Long: `Push one or more attestations to the Stash server.

Examples:
  # Push from files
  stash push attestation1.json attestation2.json

  # Push from stdin
  stash push --stdin < attestation.json
  cat attestation.json | stash push --stdin`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get organization ID
			orgID, err := opts.GetOrg()
			if err != nil {
				return err
			}

			// Get client
			c, cleanup, err := opts.NewClient(orgID, opts.Namespace)
			if err != nil {
				return fmt.Errorf("creating client: %w", err)
			}
			defer cleanup()

			// Read attestations
			var attestations [][]byte

			if opts.Stdin {
				// Read from stdin
				data, err := io.ReadAll(os.Stdin)
				if err != nil {
					return fmt.Errorf("reading stdin: %w", err)
				}
				attestations = append(attestations, data)
			} else {
				// Read from files
				if len(args) == 0 {
					return fmt.Errorf("no files specified (use --stdin to read from stdin)")
				}

				for _, path := range args {
					data, err := os.ReadFile(path)
					if err != nil {
						return fmt.Errorf("reading %s: %w", path, err)
					}
					attestations = append(attestations, data)
				}
			}

			// Push attestations
			fmt.Printf("Pushing %d attestation(s) to org %s namespace %q...\n", len(attestations), orgID, opts.Namespace)
			results, err := c.UploadAttestations(cmd.Context(), orgID, opts.Namespace, attestations)
			if err != nil {
				return fmt.Errorf("pushing attestations: %w", err)
			}

			// Print results
			successCount := 0
			for _, result := range results {
				if result.Error != "" {
					fmt.Printf("Failed: %s\n", result.Error)
				} else if result.Existed {
					fmt.Printf("Already exists: %s (hash: %s)\n", result.AttestationID, result.ContentHash)
					successCount++
				} else {
					fmt.Printf("Pushed: %s (hash: %s)\n", result.AttestationID, result.ContentHash)
					successCount++
				}
			}

			fmt.Printf("\nSuccessfully pushed %d of %d attestation(s)\n", successCount, len(results))

			return nil
		},
	}

	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}
