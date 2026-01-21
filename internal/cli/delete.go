package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

// NewDeleteCommand creates the delete command.
func NewDeleteCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <attestation-id|hash>",
		Short: "Delete an attestation from Stash",
		Long: `Delete an attestation by ID or hash from the Stash server.

This permanently removes the attestation and all its metadata.

Examples:
  # Delete by attestation ID
  stash delete abc123

  # Delete by content hash
  stash delete sha256:a1b2c3...`,
		Args: cobra.ExactArgs(1),
		RunE: runDelete,
	}

	return cmd
}

func runDelete(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	id := args[0]

	// Get client
	c, err := getClient()
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}

	// Delete attestation
	fmt.Printf("Deleting attestation %s...\n", id)
	if err := c.DeleteAttestation(ctx, id); err != nil {
		return fmt.Errorf("deleting attestation: %w", err)
	}

	fmt.Println("✓ Attestation deleted successfully")

	return nil
}
