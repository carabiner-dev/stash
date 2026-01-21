package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

var (
	readRaw       bool
	readPredicate bool
)

// NewReadCommand creates the read command.
func NewReadCommand() *cobra.Command {
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
		RunE: runRead,
	}

	cmd.Flags().BoolVar(&readRaw, "raw", false, "Return only raw attestation JSON")
	cmd.Flags().BoolVar(&readPredicate, "predicate", false, "Return only predicate JSON")

	return cmd
}

func runRead(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	id := args[0]

	// Get client
	c, err := getClient()
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}

	// Handle --raw flag
	if readRaw {
		data, err := c.GetAttestationRaw(ctx, id)
		if err != nil {
			return fmt.Errorf("reading attestation: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	// Handle --predicate flag
	if readPredicate {
		data, err := c.GetAttestationPredicate(ctx, id)
		if err != nil {
			return fmt.Errorf("reading predicate: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	// Get full attestation
	attestation, raw, predicate, err := c.GetAttestation(ctx, id)
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
}
