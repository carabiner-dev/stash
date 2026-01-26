// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/stash/pkg/client"
)

var _ command.OptionsSet = (*ListOptions)(nil)

// ListOptions
type ListOptions struct {
	PredicateType    string
	SubjectName      string
	SubjectURI       string
	SubjectNameRegex string
	SubjectURIRegex  string
	SubjectDigest    map[string]string
	SignerIdentity   string
	SignedOnly       bool
	ValidatedOnly    bool
	Limit            int
	Cursor           string
	JSON             bool
}

// defaultListOptions
var defaultListOptions = &ListOptions{
	PredicateType:    "",
	SubjectName:      "",
	SubjectURI:       "",
	SubjectNameRegex: "",
	SubjectURIRegex:  "",
	//SubjectDigest: "",
	SignerIdentity: "",
	//SignedOnly: "",
	//ValidatedOnly: "",
	Limit:  50,
	Cursor: "",
	JSON:   false,
}

func (lo *ListOptions) Validate() error {
	return nil
}

func (lo *ListOptions) Config() *command.OptionsSetConfig {
	return nil
}

func (lo *ListOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&lo.PredicateType, "predicate-type", "", "Filter by predicate type")
	cmd.Flags().StringVar(&lo.SubjectName, "subject.name", "", "Filter by exact subject name")
	cmd.Flags().StringVar(&lo.SubjectURI, "subject.uri", "", "Filter by exact subject URI")
	cmd.Flags().StringVar(&lo.SubjectNameRegex, "subject-regex.name", "", "Filter by subject name regex (max 256 chars)")
	cmd.Flags().StringVar(&lo.SubjectURIRegex, "subject-regex.uri", "", "Filter by subject URI regex (max 256 chars)")
	cmd.Flags().StringToStringVar(&lo.SubjectDigest, "subject.digest", nil, "Filter by subject digest (algo=value)")
	cmd.Flags().StringVar(&lo.SignerIdentity, "signer", "", "Filter by signer identity")
	cmd.Flags().BoolVar(&lo.SignedOnly, "signed", false, "Show only signed attestations")
	cmd.Flags().BoolVar(&lo.ValidatedOnly, "validated", false, "Show only validated attestations")
	cmd.Flags().IntVar(&lo.Limit, "limit", 50, "Maximum number of results (max 1000)")
	cmd.Flags().StringVar(&lo.Cursor, "cursor", "", "Pagination cursor token")
	cmd.Flags().BoolVar(&lo.JSON, "json", false, "Output as JSON")
}

// NewListCommand creates the list command.
func AddListCommand(parent *cobra.Command) {
	opts := defaultListOptions
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List attestations from Stash",
		Long: `List attestations with optional filters and pagination.

Examples:
  # List all attestations
  stash list

  # Filter by predicate type
  stash list --predicate-type "https://slsa.dev/provenance/v1"

  # Filter by subject name
  stash list --subject.name "my-artifact"

  # Filter by subject URI with regex
  stash list --subject-regex.uri "pkg:.*"

  # Filter by signer identity
  stash list --signer "mailto:user@example.com"

  # Show only signed and validated attestations
  stash list --signed --validated

  # Pagination
  stash list --limit 50 --cursor <token>

  # Output as JSON
  stash list --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}

			// Get client
			c, cleanup, err := getClient()
			if err != nil {
				return fmt.Errorf("creating client: %w", err)
			}
			defer cleanup()

			// Build filters
			filters := &client.Filters{
				PredicateType:    opts.PredicateType,
				SubjectName:      opts.SubjectName,
				SubjectURI:       opts.SubjectURI,
				SubjectNameRegex: opts.SubjectNameRegex,
				SubjectURIRegex:  opts.SubjectURIRegex,
				SubjectDigest:    opts.SubjectDigest,
				SignerIdentity:   opts.SignerIdentity,
				SignedOnly:       opts.SignedOnly,
				ValidatedOnly:    opts.ValidatedOnly,
			}

			cursor := &client.Cursor{
				Limit: opts.Limit,
				Token: opts.Cursor,
			}

			// List attestations
			result, err := c.ListAttestations(cmd.Context(), "", "", filters, cursor)
			if err != nil {
				return fmt.Errorf("listing attestations: %w", err)
			}

			// Output as JSON
			if opts.JSON {
				data, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					return fmt.Errorf("marshaling JSON: %w", err)
				}
				fmt.Println(string(data))
				return nil
			}

			// Output as table
			if len(result.Attestations) == 0 {
				fmt.Println("No attestations found")
				return nil
			}

			fmt.Printf("Found %d attestation(s)\n\n", len(result.Attestations))

			for i, att := range result.Attestations {
				fmt.Printf("%d. %s\n", i+1, att.ID)
				fmt.Printf("   Predicate Type: %s\n", att.PredicateType)
				fmt.Printf("   Content Hash:   %s\n", att.ContentHash[:16]+"...")
				fmt.Printf("   Signed:         %v\n", att.Signed)
				fmt.Printf("   Validated:      %v\n", att.Validated)
				if len(att.Subjects) > 0 {
					fmt.Printf("   Subjects:       %d\n", len(att.Subjects))
					for j, subject := range att.Subjects {
						if j < 3 {
							fmt.Printf("     - %s (%s)\n", subject.Name, subject.DigestAlgorithm)
						} else if j == 3 {
							fmt.Printf("     ... and %d more\n", len(att.Subjects)-3)
							break
						}
					}
				}
				fmt.Printf("   Created:        %s\n", att.CreatedAt.Format("2006-01-02 15:04:05"))
				fmt.Println()
			}

			if result.NextCursor != "" {
				fmt.Printf("Next page cursor: %s\n", result.NextCursor)
				fmt.Printf("To get next page, run: stash list --cursor %s\n", result.NextCursor)
			}

			if result.Total > 0 {
				fmt.Printf("Total attestations: %d\n", result.Total)
			}

			return nil
		},
	}

	opts.AddFlags(parent)
	parent.AddCommand(cmd)
}
