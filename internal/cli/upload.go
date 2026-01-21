// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = (*UploadOptions)(nil)

// UploadOptions holds the options for the upload command.
type UploadOptions struct {
	Stdin bool
}

var defaultUploadOptions = &UploadOptions{
	Stdin: false,
}

func (o *UploadOptions) Validate() error {
	return nil
}

func (o *UploadOptions) Config() *command.OptionsSetConfig {
	return nil
}

func (o *UploadOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.Stdin, "stdin", false, "Read attestation from stdin")
}

// AddUploadCommand adds the upload command to the parent.
func AddUploadCommand(parent *cobra.Command) {
	opts := defaultUploadOptions
	cmd := &cobra.Command{
		Use:   "upload [file...]",
		Short: "Upload attestations to Stash",
		Long: `Upload one or more attestations to the Stash server.

Examples:
  # Upload from files
  stash upload attestation1.json attestation2.json

  # Upload from stdin
  stash upload --stdin < attestation.json
  cat attestation.json | stash upload --stdin`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}

			// Get client
			c, err := getClient()
			if err != nil {
				return fmt.Errorf("creating client: %w", err)
			}

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

			// Upload attestations
			fmt.Printf("Uploading %d attestation(s)...\n", len(attestations))
			results, err := c.UploadAttestations(cmd.Context(), attestations)
			if err != nil {
				return fmt.Errorf("uploading attestations: %w", err)
			}

			// Print results
			successCount := 0
			for _, result := range results {
				if result.Error != "" {
					fmt.Printf("❌ Failed: %s\n", result.Error)
				} else if result.Existed {
					fmt.Printf("✓ Already exists: %s (hash: %s)\n", result.AttestationID, result.ContentHash)
					successCount++
				} else {
					fmt.Printf("✓ Uploaded: %s (hash: %s)\n", result.AttestationID, result.ContentHash)
					successCount++
				}
			}

			fmt.Printf("\nSuccessfully uploaded %d of %d attestation(s)\n", successCount, len(results))

			return nil
		},
	}

	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}
