// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/stash/pkg/client"
)

var _ command.OptionsSet = (*PushOptions)(nil)

// maxPushBatch is the most attestations the server accepts in one upload.
// Larger inputs are split across requests.
const maxPushBatch = 100

// splitAttestations reads every attestation in r.
//
// An input may hold a single attestation or many, one per line as JSON Lines.
// Decoding successive JSON values covers both without having to detect which
// it is: whitespace between values is insignificant to the decoder, so a
// pretty-printed attestation spanning many lines reads as one value, while a
// JSON Lines stream reads as one value per line. Splitting on lines instead
// would break the former.
func splitAttestations(r io.Reader) ([][]byte, error) {
	decoder := json.NewDecoder(r)

	var attestations [][]byte
	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				return attestations, nil
			}
			return nil, fmt.Errorf("parsing attestation %d: %w", len(attestations)+1, err)
		}
		attestations = append(attestations, raw)
	}
}

// PushOptions holds the options for the push command.
type PushOptions struct {
	ClientOptions
	Stdin     bool
	Namespace string
}

var defaultPushOptions = PushOptions{
	ClientOptions: DefaultClientOptions,
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

Each file may hold a single attestation or several, one per line in JSON Lines
format; every attestation in every file is uploaded. Inputs larger than the
server's per-request limit are uploaded in batches.

Examples:
  # Push from files
  stash push attestation1.json attestation2.json

  # Push every attestation in a JSON Lines file
  stash push attestations.jsonl

  # Push from stdin
  stash push --stdin < attestation.json
  cat attestations.jsonl | stash push --stdin`,
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
			c, cleanup, err := opts.NewClient(cmd.Context(), orgID, opts.Namespace)
			if err != nil {
				return fmt.Errorf("creating client: %w", err)
			}
			defer cleanup()

			// Read attestations
			var attestations [][]byte

			if opts.Stdin {
				// Read from stdin
				atts, err := splitAttestations(os.Stdin)
				if err != nil {
					return fmt.Errorf("reading stdin: %w", err)
				}
				attestations = atts
			} else {
				// Read from files
				if len(args) == 0 {
					return fmt.Errorf("no files specified (use --stdin to read from stdin)")
				}

				for _, path := range args {
					f, err := os.Open(path)
					if err != nil {
						return fmt.Errorf("reading %s: %w", path, err)
					}
					atts, err := splitAttestations(f)
					f.Close() //nolint:errcheck,gosec // read-only file
					if err != nil {
						return fmt.Errorf("reading %s: %w", path, err)
					}
					attestations = append(attestations, atts...)
				}
			}

			if len(attestations) == 0 {
				return errors.New("no attestations found in input")
			}

			// Push attestations. A jsonl file can hold more than the server
			// accepts per request, so upload in batches and collect the
			// results as though it had been one call.
			fmt.Printf("Pushing %d attestation(s) to org %s namespace %q...\n", len(attestations), orgID, opts.Namespace)

			var results []*client.UploadResult
			for batch := range slices.Chunk(attestations, maxPushBatch) {
				r, err := c.UploadAttestations(cmd.Context(), orgID, opts.Namespace, batch)
				if err != nil {
					return fmt.Errorf("pushing attestations: %w", err)
				}
				results = append(results, r...)
			}

			// Print results
			successCount := 0
			for _, result := range results {
				switch {
				case result.Error != "":
					fmt.Printf("Failed: %s\n", result.Error)
				case result.Existed:
					fmt.Printf("Already exists: %s (hash: %s)\n", result.AttestationID, result.ContentHash)
					successCount++
				default:
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
