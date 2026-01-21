package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

var uploadStdin bool

// NewUploadCommand creates the upload command.
func NewUploadCommand() *cobra.Command {
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
		RunE: runUpload,
	}

	cmd.Flags().BoolVar(&uploadStdin, "stdin", false, "Read attestation from stdin")

	return cmd
}

func runUpload(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get client
	c, err := getClient()
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}

	// Read attestations
	var attestations [][]byte

	if uploadStdin {
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
	results, err := c.UploadAttestations(ctx, attestations)
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
}
