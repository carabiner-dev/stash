package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/carabiner-dev/stash/pkg/client"
)

var (
	listPredicateType    string
	listSubjectName      string
	listSubjectURI       string
	listSubjectNameRegex string
	listSubjectURIRegex  string
	listSubjectDigest    map[string]string
	listSignerIdentity   string
	listSignedOnly       bool
	listValidatedOnly    bool
	listLimit            int
	listCursor           string
	listJSON             bool
)

// NewListCommand creates the list command.
func NewListCommand() *cobra.Command {
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
		RunE: runList,
	}

	cmd.Flags().StringVar(&listPredicateType, "predicate-type", "", "Filter by predicate type")
	cmd.Flags().StringVar(&listSubjectName, "subject.name", "", "Filter by exact subject name")
	cmd.Flags().StringVar(&listSubjectURI, "subject.uri", "", "Filter by exact subject URI")
	cmd.Flags().StringVar(&listSubjectNameRegex, "subject-regex.name", "", "Filter by subject name regex (max 256 chars)")
	cmd.Flags().StringVar(&listSubjectURIRegex, "subject-regex.uri", "", "Filter by subject URI regex (max 256 chars)")
	cmd.Flags().StringToStringVar(&listSubjectDigest, "subject.digest", nil, "Filter by subject digest (algo=value)")
	cmd.Flags().StringVar(&listSignerIdentity, "signer", "", "Filter by signer identity")
	cmd.Flags().BoolVar(&listSignedOnly, "signed", false, "Show only signed attestations")
	cmd.Flags().BoolVar(&listValidatedOnly, "validated", false, "Show only validated attestations")
	cmd.Flags().IntVar(&listLimit, "limit", 50, "Maximum number of results (max 1000)")
	cmd.Flags().StringVar(&listCursor, "cursor", "", "Pagination cursor token")
	cmd.Flags().BoolVar(&listJSON, "json", false, "Output as JSON")

	return cmd
}

func runList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get client
	c, err := getClient()
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}

	// Build filters
	filters := &client.Filters{
		PredicateType:    listPredicateType,
		SubjectName:      listSubjectName,
		SubjectURI:       listSubjectURI,
		SubjectNameRegex: listSubjectNameRegex,
		SubjectURIRegex:  listSubjectURIRegex,
		SubjectDigest:    listSubjectDigest,
		SignerIdentity:   listSignerIdentity,
		SignedOnly:       listSignedOnly,
		ValidatedOnly:    listValidatedOnly,
	}

	cursor := &client.Cursor{
		Limit: listLimit,
		Token: listCursor,
	}

	// List attestations
	result, err := c.ListAttestations(ctx, filters, cursor)
	if err != nil {
		return fmt.Errorf("listing attestations: %w", err)
	}

	// Output as JSON
	if listJSON {
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
}
